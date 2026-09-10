// SPDX-License-Identifier: Apache-2.0

//! Standalone CI experiment, not part of a published crate or enforcement path.
//! Checks coalition inheritance, management privileges, and versioned signals
//! against directly owned fixture children. It does not change host accounts
//! or security configuration and never signals an unrelated process.

#![cfg(target_os = "macos")]

use std::{
    error::Error,
    ffi::{c_int, c_void},
    fs, io,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::Path,
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
const DETACH_MODES: [&str; 3] = ["setsid", "setpgid", "spawn-group"];

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

// Only the documented initial two counters are requested. XNU copies the
// smaller of the caller's size and its complete resource-usage structure.
#[repr(C)]
#[derive(Default)]
struct CoalitionCounts {
    started: u64,
    exited: u64,
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
    fn proc_listallpids(buffer: *mut c_void, size: c_int) -> c_int;
    fn coalition_info_resource_usage(id: u64, buffer: *mut c_void, size: usize) -> c_int;
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
    let arguments: Vec<_> = std::env::args_os().collect();
    match arguments.get(1).and_then(|value| value.to_str()) {
        Some("family") if arguments.len() == 3 => {
            return family_service(Path::new(&arguments[2]));
        }
        Some("family-leaf") if arguments.len() == 4 => {
            return family_leaf(
                arguments[2].to_str().ok_or("non-UTF-8 fixture mode")?,
                Path::new(&arguments[3]),
            );
        }
        Some("families") if arguments.len() == 4 => {
            return probe_families(Path::new(&arguments[2]), Path::new(&arguments[3]));
        }
        _ => {}
    }
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
    for mode in DETACH_MODES {
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
    let pid =
        c_int::try_from(std::process::id()).map_err(|_| io::Error::other("process ID overflow"))?;
    process_coalitions(pid)
}

fn process_coalitions(pid: c_int) -> io::Result<CoalitionInfo> {
    let mut info = CoalitionInfo::default();
    let size = c_int::try_from(std::mem::size_of::<CoalitionInfo>())
        .map_err(|_| io::Error::other("coalition info size overflow"))?;
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

fn family_service(directory: &Path) -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    for mode in DETACH_MODES {
        let mut command = Command::new(&executable);
        command
            .args(["family-leaf", mode])
            .arg(directory)
            .stdin(Stdio::null());
        if mode == "spawn-group" {
            command.process_group(0);
        }
        // Deliberately do not wait: the experiment needs orphaned descendants.
        // Every leaf has its own finite deadline even if the controller fails.
        drop(command.spawn()?);
    }
    wait_until(|| {
        Ok(DETACH_MODES
            .iter()
            .all(|mode| directory.join(mode).exists()))
    })?;
    publish_pid(directory, "root")?;
    wait_until(|| Ok(directory.join("root-exit").exists()))?;
    Ok(())
}

fn family_leaf(mode: &str, directory: &Path) -> Result<(), Box<dyn Error>> {
    let result = match mode {
        "setsid" => unsafe { setsid() },
        "setpgid" => unsafe { setpgid(0, 0) },
        "spawn-group" => 0,
        _ => return Err("unknown family fixture mode".into()),
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    publish_pid(directory, mode)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut expanded = false;
    while Instant::now() < deadline {
        if !expanded && directory.join("grow").exists() {
            expanded = true;
            // Bounded fan-out: at most twelve additional sleepers per family,
            // all with finite lifetimes. Never an unbounded fork workload.
            for index in 0..4 {
                drop(
                    Command::new(std::env::current_exe()?)
                        .arg("signal-target")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()?,
                );
                if index == 0 {
                    fs::write(directory.join(format!("growing-{mode}")), b"spawned")?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if directory.join("pulse").exists() {
            fs::write(directory.join(format!("pulse-{mode}")), b"alive")?;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn probe_families(first: &Path, second: &Path) -> Result<(), Box<dyn Error>> {
    wait_until(|| Ok(first.join("root").exists() && second.join("root").exists()))?;
    let own = current_coalitions()?.ids[0];
    let mut owned = Vec::new();
    for directory in [first, second] {
        let pid: c_int = fs::read_to_string(directory.join("root"))?.parse()?;
        let coalition = process_coalitions(pid)?.ids[0];
        if coalition == 0 || coalition == own || owned.contains(&coalition) {
            return Err("launchd did not create an independent coalition".into());
        }
        // Verify the experiment's whole finite family while its leader
        // is alive; only these newly created launchd jobs can become targets.
        for mode in DETACH_MODES {
            let leaf: c_int = fs::read_to_string(directory.join(mode))?.parse()?;
            if process_coalitions(leaf)?.ids[0] != coalition {
                return Err(format!("{mode} did not belong to its launchd job").into());
            }
        }
        owned.push(coalition);
    }
    let result = (|| -> Result<(), Box<dyn Error>> {
        for directory in [first, second] {
            fs::write(directory.join("root-exit"), b"exit")?;
        }
        // Wait for both original parents to leave while their three detached
        // children remain accounted for by the kernel.
        wait_until(|| Ok(coalition_active(owned[0])? == 3 && coalition_active(owned[1])? == 3))?;
        println!(
            "orphan families: independent coalitions {:?}, three descendants each",
            owned
        );
        fs::write(first.join("grow"), b"create another generation")?;
        wait_until(|| {
            Ok(DETACH_MODES
                .iter()
                .all(|mode| first.join(format!("growing-{mode}")).exists()))
        })?;
        let expanded = coalition_active(owned[0])?;
        if expanded < 6 {
            return Err(
                format!("new generation was not accounted for: {expanded} active tasks").into(),
            );
        }
        println!("orphan families: first family grew to {expanded} tasks before cleanup");
        terminate_coalition_members(owned[0])?;
        if coalition_active(owned[1])? != 3 {
            return Err("terminating the first coalition affected the second".into());
        }
        fs::write(
            second.join("pulse"),
            b"reply after first family termination",
        )?;
        wait_until(|| {
            Ok(DETACH_MODES
                .iter()
                .all(|mode| second.join(format!("pulse-{mode}")).exists()))
        })?;
        terminate_coalition_members(owned[1])?;
        println!("orphan families: first empty; second remained responsive; second now empty");
        Ok(())
    })();
    // On failure, cleanup is still limited to the verified experiment IDs.
    // Finite leaf deadlines remain an independent backstop if this also fails.
    for coalition in owned {
        if let Err(error) = terminate_coalition_members(coalition) {
            eprintln!("fixture coalition {coalition} cleanup: {error}");
        }
    }
    result
}

fn coalition_active(id: u64) -> io::Result<u64> {
    let mut counts = CoalitionCounts::default();
    // The kernel accepts a prefix-sized buffer; no trailing fields are read.
    let result = unsafe {
        coalition_info_resource_usage(
            id,
            (&mut counts as *mut CoalitionCounts).cast(),
            std::mem::size_of_val(&counts),
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        // Only previously verified, monotonically allocated coalition IDs
        // reach here. ESRCH means launchd has already reaped this empty job.
        if error.raw_os_error() == Some(ESRCH) {
            return Ok(0);
        }
        return Err(error);
    }
    counts
        .started
        .checked_sub(counts.exited)
        .ok_or_else(|| io::Error::other("inconsistent coalition counts"))
}

fn process_identity(pid: c_int) -> io::Result<ProcessIdentity> {
    let mut identity = ProcessIdentity::default();
    let size = c_int::try_from(std::mem::size_of_val(&identity)).map_err(io::Error::other)?;
    let bytes = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&mut identity as *mut ProcessIdentity).cast(),
            size,
        )
    };
    if bytes <= 0 {
        return Err(io::Error::last_os_error());
    }
    if bytes != size {
        return Err(io::Error::other("incomplete process identity"));
    }
    Ok(identity)
}

fn terminate_coalition_members(coalition: u64) -> io::Result<()> {
    wait_until(|| {
        let mut pids = vec![0 as c_int; 256];
        loop {
            let size = c_int::try_from(std::mem::size_of_val(pids.as_slice()))
                .map_err(io::Error::other)?;
            let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), size) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            let count = usize::try_from(count).map_err(io::Error::other)?;
            if count < pids.len() {
                pids.truncate(count);
                break;
            }
            pids.resize(
                pids.len()
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("PID buffer overflow"))?,
                0,
            );
        }
        for pid in pids.into_iter().filter(|pid| *pid > 0) {
            let Ok(before) = process_identity(pid) else {
                continue;
            };
            let Ok(info) = process_coalitions(pid) else {
                continue;
            };
            if info.ids[0] != coalition {
                continue;
            }
            let Ok(after) = process_identity(pid) else {
                continue;
            };
            if before.unique_id != after.unique_id || before.version != after.version {
                continue;
            }
            let mut token = [0u32; 8];
            token[5] = u32::try_from(pid).map_err(io::Error::other)?;
            token[7] = after.version as u32;
            // Membership is immutable. Matching identities bracket its read,
            // and the kernel checks the same version atomically with SIGKILL.
            let result = unsafe { proc_signal_with_audittoken(&mut token, SIGKILL) };
            if result != 0 && result != ESRCH {
                return Err(io::Error::from_raw_os_error(result));
            }
        }
        // A PID snapshot can miss a racing fork. Only kernel accounting, not
        // the empty snapshot, can complete this experiment's termination loop.
        Ok(coalition_active(coalition)? == 0)
    })
}

fn wait_until(mut predicate: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if predicate()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lifecycle experiment deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn publish_pid(directory: &Path, name: &str) -> io::Result<()> {
    let staging = directory.join(format!("{name}.staging"));
    fs::write(&staging, std::process::id().to_string())?;
    fs::rename(staging, directory.join(name))
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
