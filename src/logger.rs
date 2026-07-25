use std::fmt::{Debug, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::config::Profile;

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Prevents secret-bearing values from being exposed through formatting or logs.
pub struct Redacted<T>(pub T);

impl<T> Debug for Redacted<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl<T> Display for Redacted<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

pub fn init() {
    let log_dir = Profile::config_dir().join("logs");
    fs::create_dir_all(&log_dir).ok();

    let latest = log_dir.join("latest.log");

    if latest.exists() {
        let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S%.3f");
        let gz_path = log_dir.join(format!("{timestamp}.log.gz"));

        if let Ok(data) = fs::read(&latest)
            && let Ok(gz_file) = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&gz_path)
        {
            let mut encoder = GzEncoder::new(gz_file, Compression::default());
            if encoder.write_all(&data).is_ok() && encoder.finish().is_ok() {
                let _ = fs::remove_file(&latest);
            } else {
                let _ = fs::remove_file(&gz_path);
            }
        }
    }

    let _ = LOG_DIR.set(log_dir.clone());

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let _ = fs::write(
        log_dir.join("latest.log"),
        format!("[{timestamp}] === Starling started ===\n"),
    );
}

fn log(level: &str, msg: &str) {
    let Some(dir) = LOG_DIR.get() else { return };
    let path = dir.join("latest.log");

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let line = format!("[{timestamp}] {level}{msg}\n");

    if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}

pub fn info(msg: &str) {
    log("INFO:  ", msg);
}

pub fn error(msg: &str) {
    log("ERROR: ", msg);
}

pub fn warn(msg: &str) {
    log("WARN:  ", msg);
}

#[cfg(test)]
mod tests {
    use super::Redacted;

    #[test]
    fn secret_formatting_is_always_redacted() {
        let secret = Redacted([42_u8; 32]);
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }
}
