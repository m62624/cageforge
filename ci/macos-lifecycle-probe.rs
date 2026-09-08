// SPDX-License-Identifier: Apache-2.0

//! Standalone CI experiment, not part of a published crate or enforcement path.
//! Checks coalition inheritance, management privileges, and versioned signals
//! against directly owned fixture children. It does not change host accounts
//! or security configuration and never signals an unrelated process.

#![cfg(target_os = "macos")]

use std::{
    error::Error,
    ffi::{c_int, c_void},
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// Apple XNU bsd/sys/proc_info_private.h and osfmk/mach/coalition.h.
const PROC_PIDCOALITIONINFO: c_int = 20;
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;
const COALITION_RESOURCE_FLAGS: u32 = 0;
const COALITION_JETSAM_FLAGS: u32 = 1 << 4;
const SIGKILL: c_int = 9;
const ESRCH: c_int = 3;

struct FixtureChild(Child);

#[repr(C)]
#[derive(Default)]
struct CoalitionInfo {
    ids: [u64; 2],
    reserved: [u64; 3],
}

#[repr(C)]
#[derive(Default)]
struct ProcessIdentity {
    uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    version: i32,
    reserved: u32,
    reserved_more: [u64; 2],
}

unsafe extern "C" {
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buf: *mut c_void, size: c_int) -> c_int;
    fn coalition_create(id: *mut u64, flags: u32) -> c_int;
    fn coalition_terminate(id: u64, flags: u32) -> c_int;
    fn coalition_reap(id: u64, flags: u32) -> c_int;
    fn geteuid() -> u32;
    fn setsid() -> c_int;
    fn setpgid(pid: c_int, pgid: c_int) -> c_int;
    fn proc_signal_with_audittoken(token: *mut [u32; 8], signal: c_int) -> c_int;
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        // Only a direct child that has not been detached/reaped is owned here.
        // Ensure a failed diagnostic cannot leave its finite sleeper behind.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Some(mode) = std::env::args().nth(1) {
        if mode == "signal-target" {
            std::thread::sleep(Duration::from_secs(20));
            return Ok(());
        }
        // Only this short-lived, directly owned fixture changes its group.
        let changed = match mode.as_str() {
            "setsid" => unsafe { setsid() },
            "setpgid" => unsafe { setpgid(0, 0) },
            "spawn-group" => 0,
            _ => return Err("unknown probe mode".into()),
        };
        if changed < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let info = current_coalitions()?;
        println!("{} {}", info.ids[0], info.ids[1]);
        return Ok(());
    }

    let info = current_coalitions()?;
    // geteuid has no pointer arguments or preconditions.
    println!("uid={} coalitions={:?}", unsafe { geteuid() }, info.ids);
    let executable = std::env::current_exe()?;
    for mode in ["setsid", "setpgid", "spawn-group"] {
        let mut command = Command::new(&executable);
        command.arg(mode).stdin(Stdio::null());
        if mode == "spawn-group" {
            command.process_group(0);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!(
                "{mode} failed: {}; {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let observed = std::str::from_utf8(&output.stdout)?.trim();
        let expected = format!("{} {}", info.ids[0], info.ids[1]);
        if observed != expected {
            return Err(format!("{mode}: expected {expected}, observed {observed}").into());
        }
        println!("{mode}: coalition membership preserved ({observed})");
    }

    probe_management("resource", COALITION_RESOURCE_FLAGS)?;
    probe_management("jetsam", COALITION_JETSAM_FLAGS)?;
    probe_versioned_signal()?;
    println!("probe complete");
    Ok(())
}

fn probe_versioned_signal() -> Result<(), Box<dyn Error>> {
    let mut child = FixtureChild(
        Command::new(std::env::current_exe()?)
            .arg("signal-target")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let pid = c_int::try_from(child.0.id())?;
    let mut identity = ProcessIdentity::default();
    let size = c_int::try_from(std::mem::size_of::<ProcessIdentity>())?;
    // The API writes a fixed-layout process identity into the exact-size buffer.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&mut identity as *mut ProcessIdentity).cast(),
            size,
        )
    };
    if written != size {
        return Err(format!(
            "identity read: {written} bytes; {}",
            io::Error::last_os_error()
        )
        .into());
    }
    let mut token = [0u32; 8];
    token[5] = child.0.id();
    token[7] = identity.version as u32 ^ 1;
    // XNU validates PID and version while holding the target process reference.
    // The mismatched token must not deliver SIGKILL to the live direct child.
    let stale_result = unsafe { proc_signal_with_audittoken(&mut token, SIGKILL) };
    if stale_result != ESRCH || child.0.try_wait()?.is_some() {
        return Err(format!("stale audit token was not rejected safely: {stale_result}").into());
    }
    token[7] = identity.version as u32;
    let result = unsafe { proc_signal_with_audittoken(&mut token, SIGKILL) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result).into());
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if status.signal() != Some(SIGKILL) {
                return Err(format!("unexpected signal-target exit: {status}").into());
            }
            println!("versioned signal: stale token rejected; exact child killed and reaped");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("versioned signal did not terminate its direct target promptly".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn current_coalitions() -> io::Result<CoalitionInfo> {
    let mut info = CoalitionInfo::default();
    let size = c_int::try_from(std::mem::size_of::<CoalitionInfo>())
        .map_err(|_| io::Error::other("coalition info size overflow"))?;
    let pid =
        c_int::try_from(std::process::id()).map_err(|_| io::Error::other("process ID overflow"))?;
    // The fixed flavor writes exactly proc_pidcoalitioninfo into a writable,
    // correctly aligned buffer of its declared size. Reject partial results.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDCOALITIONINFO,
            0,
            (&mut info as *mut CoalitionInfo).cast(),
            size,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size {
        return Err(io::Error::other("incomplete coalition info"));
    }
    Ok(info)
}

fn probe_management(kind: &str, flags: u32) -> io::Result<()> {
    let mut id = 0;
    // A successful call creates a new EMPTY coalition owned by this experiment.
    // No process is ever inserted into it; cleanup never targets an existing ID.
    if unsafe { coalition_create(&mut id, flags) } != 0 {
        println!(
            "{kind} coalition_create unavailable: {}",
            io::Error::last_os_error()
        );
        return Ok(());
    }
    // Both calls take the exact ID just returned by create, not a PID or PGID.
    let terminated = unsafe { coalition_terminate(id, 0) };
    let terminate_error = (terminated != 0).then(io::Error::last_os_error);
    let reaped = unsafe { coalition_reap(id, 0) };
    let reap_error = (reaped != 0).then(io::Error::last_os_error);
    if let Some(error) = terminate_error.or(reap_error) {
        eprintln!("empty {kind} coalition {id} cleanup failed");
        return Err(error);
    }
    println!("{kind} coalition_create permitted; empty coalition {id} reaped");
    Ok(())
}
