#[cfg(unix)]
pub fn suppress_stderr<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use std::os::unix::io::RawFd;

    const STDERR: RawFd = 2;

    unsafe {
        let saved = libc::dup(STDERR);
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_WRONLY);

        if devnull >= 0 && saved >= 0 {
            libc::dup2(devnull, STDERR);
        }

        let result = f();

        if saved >= 0 {
            libc::dup2(saved, STDERR);
            libc::close(saved);
        }
        if devnull >= 0 {
            libc::close(devnull);
        }

        result
    }
}

#[cfg(not(unix))]
pub fn suppress_stderr<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}
