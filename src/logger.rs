use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use flate2::Compression;
use flate2::write::GzEncoder;

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn init() {
    let log_dir = PathBuf::from("logs");
    fs::create_dir_all(&log_dir).ok();

    let latest = log_dir.join("latest.log");

    if latest.exists() {
        let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
        let gz_path = log_dir.join(format!("{timestamp}.log.gz"));

        if let Ok(data) = fs::read(&latest) {
            if let Ok(gz_file) = File::create(&gz_path) {
                let mut encoder = GzEncoder::new(gz_file, Compression::default());
                let _ = encoder.write_all(&data);
                let _ = encoder.finish();
            }
        }

        let _ = fs::remove_file(&latest);
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
