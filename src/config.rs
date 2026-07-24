use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub pronouns: String,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub text_color: String,
    pub bg_color: String,
    pub border_color: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: String::new(),
            pronouns: String::new(),
            input_device: None,
            output_device: None,
            text_color: "#CFD6D2".into(),
            bg_color: String::new(),
            border_color: "#333B37".into(),
        }
    }
}

impl Profile {
    pub fn config_dir() -> PathBuf {
        if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
            PathBuf::from(home).join(".config").join("starling")
        } else if let Some(appdata) = std::env::var_os("APPDATA").filter(|value| !value.is_empty())
        {
            PathBuf::from(appdata).join("starling")
        } else {
            PathBuf::from(".starling")
        }
    }

    pub fn roosts_dir() -> PathBuf {
        Self::config_dir().join("roosts")
    }

    fn config_path() -> PathBuf {
        Self::config_dir().join("profile.bin")
    }

    pub fn load() -> Option<Self> {
        Self::try_load().ok()
    }

    pub fn try_load() -> anyhow::Result<Self> {
        let path = Self::config_path();
        let data = std::fs::read(&path)
            .with_context(|| format!("failed to read profile at {}", path.display()))?;
        postcard::from_bytes(&data)
            .with_context(|| format!("profile at {} is invalid", path.display()))
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create config directory {}", dir.display()))?;
        let data = postcard::to_stdvec(self).context("failed to serialize profile")?;
        let path = Self::config_path();
        std::fs::write(&path, data)
            .with_context(|| format!("failed to write profile at {}", path.display()))?;
        Ok(())
    }

    pub fn to_code(&self) -> String {
        let mut len = self.name.len().min(15);
        while !self.name.is_char_boundary(len) {
            len -= 1;
        }
        let name_bytes = &self.name.as_bytes()[..len];
        let mut buf = [0u8; 16];
        buf[0] = len as u8;
        buf[1..1 + len].copy_from_slice(name_bytes);
        data_encoding::HEXUPPER.encode(&buf)
    }

    pub fn from_code(code: &str) -> Option<Self> {
        let bytes = data_encoding::HEXUPPER.decode(code.as_bytes()).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        let len = bytes[0] as usize;
        if len > 15 {
            return None;
        }
        let name = String::from_utf8(bytes[1..1 + len].to_vec()).ok()?;
        Some(Profile {
            name,
            ..Default::default()
        })
    }

    pub fn load_or_create_secret() -> iroh::SecretKey {
        Self::try_load_or_create_secret().unwrap_or_else(|error| {
            crate::logger::error(&format!("failed to persist identity key: {error}"));
            iroh::SecretKey::generate()
        })
    }

    pub fn try_load_or_create_secret() -> anyhow::Result<iroh::SecretKey> {
        let dir = Self::config_dir();
        let path = dir.join("identity.key");
        match std::fs::read(&path) {
            Ok(bytes) => return secret_from_bytes(&path, &bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read identity key at {}", path.display()));
            }
        }

        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create config directory {}", dir.display()))?;
        let key = iroh::SecretKey::generate();
        match create_secret_file(&path, &key.to_bytes()) {
            Ok(()) => Ok(key),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let bytes = std::fs::read(&path).with_context(|| {
                    format!(
                        "failed to read concurrently-created key at {}",
                        path.display()
                    )
                })?;
                secret_from_bytes(&path, &bytes)
            }
            Err(error) => Err(error)
                .with_context(|| format!("failed to persist identity key at {}", path.display())),
        }
    }
}

fn secret_from_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<iroh::SecretKey> {
    let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
        bail!(
            "identity key at {} must be exactly 32 bytes",
            path.display()
        );
    };
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

fn create_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn profile_code_truncates_on_utf8_boundary() {
        let profile = Profile {
            name: "abcdefghijklmn🦅".into(),
            ..Profile::default()
        };

        let decoded = Profile::from_code(&profile.to_code()).expect("valid profile code");
        assert_eq!(decoded.name, "abcdefghijklmn");
    }
}
