use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

static STATE: OnceLock<PathBuf> = OnceLock::new();

const ROTATE_SIZE: u64 = 8 * 1024 * 1024;

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

/// Initialize the log file. Idempotent — safe to call from every subcommand.
/// Rotates only when `latest.log` exceeds the size threshold, not on every
/// invocation. Returns an error only if the log directory cannot be created.
pub fn init() -> anyhow::Result<()> {
    if STATE.get().is_some() {
        return Ok(());
    }
    let dir = crate::config::Profile::config_dir().join("logs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("latest.log");
    if std::fs::metadata(&path)
        .map(|m| m.len() > ROTATE_SIZE)
        .unwrap_or(false)
    {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.6f");
        let _ = std::fs::rename(&path, dir.join(format!("log-{stamp}.log")));
    }
    let _ = STATE.set(path);
    Ok(())
}

fn write(level: &str, msg: &str) {
    let line = format!("{} {level} {msg}\n", chrono::Utc::now().to_rfc3339());
    match STATE.get() {
        Some(path) => {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                if file.write_all(line.as_bytes()).is_err() {
                    eprint!("{line}");
                }
            } else {
                eprint!("{line}");
            }
        }
        None => eprint!("{line}"),
    }
}

pub fn info(msg: &str) {
    write("INFO", msg);
}

pub fn warn(msg: &str) {
    write("WARN", msg);
}

pub fn error(msg: &str) {
    write("ERROR", msg);
}

/// Log a short fingerprint, NEVER the secret. Applies to invites, keys,
/// certificates, message bodies and media — none of which may be logged in full.
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
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

    #[test]
    fn fingerprint_is_short_and_deterministic() {
        let fp = super::fingerprint(b"invite-secret");
        assert_eq!(fp.len(), 8);
        assert_eq!(fp, super::fingerprint(b"invite-secret"));
        assert_ne!(fp, super::fingerprint(b"different-secret"));
    }
}
