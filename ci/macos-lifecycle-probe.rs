// SPDX-License-Identifier: Apache-2.0

//! Standalone CI experiment, not part of a published crate or enforcement path.
//! Checks coalition inheritance and management privileges without signalling
//! any process or changing the machine's accounts or security configuration.

#![cfg(target_os = "macos")]

use std::{
    error::Error,
    ffi::{c_int, c_void},
    io,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

// Apple XNU bsd/sys/proc_info_private.h and osfmk/mach/coalition.h.
const PROC_PIDCOALITIONINFO: c_int = 20;
const COALITION_RESOURCE_FLAGS: u32 = 0;
const COALITION_JETSAM_FLAGS: u32 = 1 << 4;

#[repr(C)]
#[derive(Default)]
struct CoalitionInfo {
    ids: [u64; 2],
    reserved: [u64; 3],
}

unsafe extern "C" {
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buf: *mut c_void, size: c_int) -> c_int;
    fn coalition_create(id: *mut u64, flags: u32) -> c_int;
    fn coalition_terminate(id: u64, flags: u32) -> c_int;
    fn coalition_reap(id: u64, flags: u32) -> c_int;
    fn geteuid() -> u32;
    fn setsid() -> c_int;
    fn setpgid(pid: c_int, pgid: c_int) -> c_int;
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Some(mode) = std::env::args().nth(1) {
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
    println!("probe complete");
    Ok(())
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
