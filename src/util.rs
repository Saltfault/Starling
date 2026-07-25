#[cfg(unix)]
pub fn suppress_stderr<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use std::os::unix::io::RawFd;
    use std::sync::{Mutex, OnceLock};

    const STDERR: RawFd = 2;
    static STDERR_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct StderrGuard {
        saved: RawFd,
        devnull: RawFd,
        redirected: bool,
    }

    impl Drop for StderrGuard {
        fn drop(&mut self) {
            unsafe {
                if self.redirected {
                    libc::dup2(self.saved, STDERR);
                }
                if self.saved >= 0 {
                    libc::close(self.saved);
                }
                if self.devnull >= 0 {
                    libc::close(self.devnull);
                }
            }
        }
    }

    let _lock = STDERR_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let guard = unsafe {
        let saved = libc::dup(STDERR);
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        let redirected = saved >= 0 && devnull >= 0 && libc::dup2(devnull, STDERR) >= 0;
        StderrGuard {
            saved,
            devnull,
            redirected,
        }
    };

    let result = f();
    drop(guard);
    result
}

#[cfg(not(unix))]
pub fn suppress_stderr<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}
