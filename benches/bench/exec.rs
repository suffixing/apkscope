//! One subprocess: spawn it, time it, take its stdout, and read its peak RSS when it
//! exits. The platform differences live in `child_usage` — `wait4(2)` on unix,
//! `GetProcessMemoryInfo` on Windows — behind one `wait`; supporting another OS means
//! another `child_usage` module and nothing else.

use std::{
    io::Read as _,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Instant,
};

#[cfg(unix)]
mod child_usage {
    //! `wait4(2)` returns the exit status *and* `ru_maxrss` — the child's peak RSS — in
    //! one call: no polling, no race with a short-lived child, and no new dependency,
    //! because the C library is already linked by std. 64-bit layout: two `struct
    //! timeval` (16 B each), then `ru_maxrss` at offset 32 — the same field order on Linux
    //! and macOS; the unit differs (KiB on Linux, bytes on macOS).

    use std::{io, process::Child};

    #[repr(C)]
    struct RUsage([u8; 144]);

    unsafe extern "C" {
        fn wait4(pid: i32, status: *mut i32, options: i32, usage: *mut RUsage) -> i32;
    }

    /// Wait for the child; returns `(exit, peak RSS in bytes)`. A death by signal is a
    /// negative exit. If `wait4` fails, fall back to `Child::wait` with the RSS unknown.
    pub fn wait(child: &mut Child) -> io::Result<(i32, Option<u64>)> {
        let mut status: i32 = 0;
        let mut usage = RUsage([0; 144]);
        let pid = child.id() as i32;
        // SAFETY: `status`/`usage` are valid out-parameters, `pid` is our own child, and
        // nothing reaps it first — std's `Child::wait` is never called on the success path.
        let r = unsafe { wait4(pid, &mut status, 0, &mut usage) };
        if r < 0 {
            let e = io::Error::last_os_error();
            let st = child.wait().map_err(|_| e)?;
            return Ok((st.code().unwrap_or(-1), None));
        }
        // WIFEXITED/WEXITSTATUS/WTERMSIG by hand — the libc macros, without the crate
        let code = (status >> 8) & 0xff;
        let sig = status & 0x7f;
        let exit = if sig == 0 { code } else { -sig };
        let peak = if cfg!(target_pointer_width = "64") {
            // ru_maxrss sits right after the two timevals on every 64-bit unix
            let raw = i64::from_ne_bytes(usage.0[32..40].try_into().expect("8 bytes"));
            let scale = if cfg!(target_os = "macos") { 1 } else { 1024 };
            u64::try_from(raw).ok().map(|v| v * scale)
        } else {
            None
        };
        Ok((exit, peak))
    }
}

#[cfg(windows)]
mod child_usage {
    //! Peak RSS of a child via `OpenProcess` + `GetProcessMemoryInfo`: kernel32 is
    //! already linked by std, and psapi is an OS import library, not a dependency.

    use std::{ffi::c_void, process::Child};

    #[repr(C)]
    struct MemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_non_paged: usize,
        quota_non_paged: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    // `GetProcessMemoryInfo` belongs to psapi per Microsoft's docs — kernel32
    // exports it only as `K32GetProcessMemoryInfo`, so a kernel32 link leaves
    // windows-gnu builds with an undefined symbol. psapi is a stock import
    // library on both the MSVC and the GNU toolchain.
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut MemoryCounters,
            cb: u32,
        ) -> i32;
    }

    /// A process handle kept open so the peak RSS stays queryable after `Child::wait`.
    pub struct Handle(*mut c_void);

    pub fn open(pid: u32) -> Option<Handle> {
        // SAFETY: plain Win32 calls with an integer pid.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() { None } else { Some(Handle(h)) }
    }

    impl Handle {
        pub fn peak_rss(&self) -> Option<u64> {
            // SAFETY: `m` is a valid out-parameter of the size its `cb` declares.
            let mut m: MemoryCounters = unsafe { std::mem::zeroed() };
            m.cb = std::mem::size_of::<MemoryCounters>() as u32;
            let ok = unsafe { GetProcessMemoryInfo(self.0, &mut m, m.cb) };
            (ok != 0).then(|| m.peak_working_set as u64)
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcess and is closed exactly once.
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// Wait for the child; returns `(exit, peak RSS in bytes)` from the kept handle.
    pub fn wait(child: &mut Child, handle: &Option<Handle>) -> std::io::Result<(i32, Option<u64>)> {
        let st = child.wait()?;
        let peak = handle.as_ref().and_then(|h| h.peak_rss());
        Ok((st.code().unwrap_or(-1), peak))
    }
}

pub(crate) struct RunOut {
    pub(crate) seconds: f64,
    pub(crate) peak_rss: Option<u64>,
    pub(crate) exit: i32,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
}

/// Spawn `exe args` (in `cwd`, when given), time it, and take its peak RSS and stdout.
/// stdout is read to EOF before waiting; stderr is drained on a thread so a chatty child
/// cannot block on a full pipe.
pub(crate) fn run_once(exe: &Path, args: &[String], cwd: Option<&Path>) -> Result<RunOut, String> {
    let mut cmd = Command::new(exe);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let start = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", exe.display()))?;

    #[cfg(windows)]
    let handle = child_usage::open(child.id());

    let err_reader = {
        let pipe = child.stderr.take();
        thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut v);
            }
            v
        })
    };
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut stdout);
    }
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).to_string();

    #[cfg(unix)]
    let (exit, peak_rss) =
        child_usage::wait(&mut child).map_err(|e| format!("{}: {e}", exe.display()))?;
    #[cfg(windows)]
    let (exit, peak_rss) =
        child_usage::wait(&mut child, &handle).map_err(|e| format!("{}: {e}", exe.display()))?;

    Ok(RunOut {
        seconds: start.elapsed().as_secs_f64(),
        peak_rss,
        exit,
        stdout,
        stderr,
    })
}
