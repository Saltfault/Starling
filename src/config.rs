use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_TEXT_COLOR: &str = "#CFD6D2";
pub const DEFAULT_BG_COLOR: &str = "";
pub const DEFAULT_BORDER_COLOR: &str = "#333B37";
pub const DEFAULT_ACCENT_COLOR: &str = "#6FAE9D";
pub const DEFAULT_AUTHOR_COLOR: &str = "#F48A52";
pub const DEFAULT_SELECTION_COLOR: &str = "#E0D267";
pub const DEFAULT_DIM_COLOR: &str = "#5F6862";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub pronouns: String,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub text_color: String,
    pub bg_color: String,
    pub border_color: String,
    pub accent_color: String,
    pub author_color: String,
    pub selection_color: String,
    pub dim_color: String,
}

#[derive(Serialize, Deserialize)]
struct LegacyProfile {
    name: String,
    pronouns: String,
    input_device: Option<String>,
    output_device: Option<String>,
    text_color: String,
    bg_color: String,
    border_color: String,
}

impl From<LegacyProfile> for Profile {
    fn from(legacy: LegacyProfile) -> Self {
        Self {
            name: legacy.name,
            pronouns: legacy.pronouns,
            input_device: legacy.input_device,
            output_device: legacy.output_device,
            text_color: legacy.text_color,
            bg_color: legacy.bg_color,
            border_color: legacy.border_color,
            ..Self::default()
        }
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            name: String::new(),
            pronouns: String::new(),
            input_device: None,
            output_device: None,
            text_color: DEFAULT_TEXT_COLOR.into(),
            bg_color: DEFAULT_BG_COLOR.into(),
            border_color: DEFAULT_BORDER_COLOR.into(),
            accent_color: DEFAULT_ACCENT_COLOR.into(),
            author_color: DEFAULT_AUTHOR_COLOR.into(),
            selection_color: DEFAULT_SELECTION_COLOR.into(),
            dim_color: DEFAULT_DIM_COLOR.into(),
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
            .or_else(|_| postcard::from_bytes::<LegacyProfile>(&data).map(Profile::from))
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
    use super::{
        DEFAULT_ACCENT_COLOR, DEFAULT_AUTHOR_COLOR, DEFAULT_DIM_COLOR, DEFAULT_SELECTION_COLOR,
        LegacyProfile, Profile,
    };

    #[test]
    fn legacy_profile_uses_default_palette() {
        let legacy = LegacyProfile {
            name: "Bird".into(),
            pronouns: "they/them".into(),
            input_device: None,
            output_device: None,
            text_color: "#010203".into(),
            bg_color: String::new(),
            border_color: "#040506".into(),
        };
        let data = postcard::to_stdvec(&legacy).expect("serialize legacy profile");
        let profile = postcard::from_bytes::<Profile>(&data)
            .or_else(|_| postcard::from_bytes::<LegacyProfile>(&data).map(Profile::from))
            .expect("migrate legacy profile");

        assert_eq!(profile.text_color, "#010203");
        assert_eq!(profile.border_color, "#040506");
        assert_eq!(profile.accent_color, DEFAULT_ACCENT_COLOR);
        assert_eq!(profile.author_color, DEFAULT_AUTHOR_COLOR);
        assert_eq!(profile.selection_color, DEFAULT_SELECTION_COLOR);
        assert_eq!(profile.dim_color, DEFAULT_DIM_COLOR);
    }

    #[test]
    fn palette_fields_round_trip() {
        let profile = Profile {
            accent_color: "#010203".into(),
            author_color: "#040506".into(),
            selection_color: "#070809".into(),
            dim_color: "#0A0B0C".into(),
            ..Profile::default()
        };
        let data = postcard::to_stdvec(&profile).expect("serialize profile");
        let decoded: Profile = postcard::from_bytes(&data).expect("deserialize profile");

        assert_eq!(decoded.accent_color, profile.accent_color);
        assert_eq!(decoded.author_color, profile.author_color);
        assert_eq!(decoded.selection_color, profile.selection_color);
        assert_eq!(decoded.dim_color, profile.dim_color);
    }

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
