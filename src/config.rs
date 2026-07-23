use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Profile {
    pub name: String,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
}

impl Profile {
    pub fn config_dir() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config").join("starling")
        } else if let Ok(appdata) = std::env::var("APPDATA") {
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
        let data = std::fs::read(Self::config_path()).ok()?;
        postcard::from_bytes(&data).ok()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let data = postcard::to_stdvec(self)?;
        std::fs::write(Self::config_path(), data)?;
        Ok(())
    }

    pub fn to_code(&self) -> String {
        let name_bytes = self.name.as_bytes();
        let len = name_bytes.len().min(15) as u8;
        let mut buf = [0u8; 16];
        buf[0] = len;
        buf[1..1 + len as usize].copy_from_slice(&name_bytes[..len as usize]);
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
            input_device: None,
            output_device: None,
        })
    }

    pub fn load_or_create_secret() -> iroh::SecretKey {
        let path = Self::config_dir().join("identity.key");
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return iroh::SecretKey::from_bytes(&arr);
            }
        }

        let key = iroh::SecretKey::generate();
        let _ = std::fs::create_dir_all(Self::config_dir());
        let _ = std::fs::write(&path, key.to_bytes());
        key
    }
}
