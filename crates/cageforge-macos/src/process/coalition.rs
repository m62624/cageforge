// SPDX-License-Identifier: Apache-2.0

//! Kernel-accounted launch ownership, independent of process groups.
//! The caller authenticates the helper before adopting its coalition and keeps
//! all enforcement guards until a completed cleanup round is confirmed.

use std::{collections::TryReserveError, io, sync::OnceLock};

use thiserror::Error;

use super::identity::ProcessIdentity;

const PROC_PIDCOALITIONINFO: libc::c_int = 20;
const INITIAL_PID_CAPACITY: usize = 64;
static RESOURCE_USAGE: OnceLock<Option<ResourceUsage>> = OnceLock::new();

pub(super) struct Coalition {
    id: u64,
    helper: ProcessIdentity,
}

#[derive(Debug, Error)]
pub(super) enum CoalitionError {
    #[error("coalition resource accounting is unavailable")]
    AccountingUnavailable,
    #[error("failed to inspect process {pid}: {source}")]
    Process { pid: libc::pid_t, source: io::Error },
    #[error("process {pid} returned {actual} coalition bytes instead of {expected}")]
    RecordSize {
        pid: libc::pid_t,
        expected: libc::c_int,
        actual: libc::c_int,
    },
    #[error("process {pid} did not have a resource coalition")]
    MissingMembership { pid: libc::pid_t },
    #[error("the helper generation changed while acquiring its coalition")]
    HelperChanged,
    #[error("the authenticated application generation changed while acquiring the coalition")]
    ApplicationChanged,
    #[error("only the executing helper may exclude itself from coalition cleanup")]
    WrongCleanupOwner,
    #[error("the helper shares the application's coalition")]
    SharedApplicationCoalition,
    #[error("failed to read coalition {id} accounting: {source}")]
    Accounting { id: u64, source: io::Error },
    #[error("coalition {id} has more exited tasks ({exited}) than started tasks ({started})")]
    InconsistentAccounting { id: u64, started: u64, exited: u64 },
    #[error("failed to enumerate native processes: {source}")]
    Enumeration { source: io::Error },
    #[error("the native PID snapshot exceeds the representable buffer size")]
    SnapshotSize,
    #[error("could not allocate the PID snapshot: {source}")]
    SnapshotAllocation { source: TryReserveError },
    #[error("failed to signal owned process {pid}: {source}")]
    Signal { pid: libc::pid_t, source: io::Error },
}

#[repr(C)]
#[derive(Default)]
struct NativeMembership {
    ids: [u64; 2],
    reserved: [u64; 3],
}

// XNU copies min(caller size, kernel structure size). These two initial
// counters are the only fields used; no version-dependent tail is read.
#[repr(C)]
#[derive(Default)]
struct NativeAccounting {
    started: u64,
    exited: u64,
}

type ResourceUsage = unsafe extern "C" fn(u64, *mut libc::c_void, usize) -> libc::c_int;

impl Coalition {
    /// Caller must obtain this process identity from its authenticated helper,
    /// not from a PID in an untrusted response body or process-name search.
    pub(super) fn from_authenticated_helper(
        helper: ProcessIdentity,
    ) -> Result<Self, CoalitionError> {
        Self::adopt(helper, current_identity()?)
    }

    pub(super) fn from_authenticated_parent(
        application: ProcessIdentity,
    ) -> Result<Self, CoalitionError> {
        Self::adopt(current_identity()?, application)
    }

    fn adopt(
        helper: ProcessIdentity,
        application: ProcessIdentity,
    ) -> Result<Self, CoalitionError> {
        accounting_api()?;
        let application_id = membership(application.pid())?;
        let id = membership(helper.pid())?;
        if id == application_id {
            return Err(CoalitionError::SharedApplicationCoalition);
        }
        if !generation_present(&helper)? {
            return Err(CoalitionError::HelperChanged);
        }
        if !generation_present(&application)? {
            return Err(CoalitionError::ApplicationChanged);
        }
        // A PID generation supplied by the authenticated message precedes the
        // membership read; recapture above closes the PID-reuse/exec interval.
        Ok(Self { id, helper })
    }

    pub(super) fn active_tasks(&self) -> Result<u64, CoalitionError> {
        let query = accounting_api()?;
        let mut counts = NativeAccounting::default();
        #[allow(unsafe_code)]
        let result = unsafe {
            query(
                self.id,
                (&mut counts as *mut NativeAccounting).cast(),
                std::mem::size_of_val(&counts),
            )
        };
        if result != 0 {
            let source = io::Error::last_os_error();
            // Only adopted, nonzero, monotonically allocated coalition IDs
            // reach this query. ESRCH means launchd already reaped this ID.
            if source.raw_os_error() == Some(libc::ESRCH) {
                return Ok(0);
            }
            return Err(CoalitionError::Accounting {
                id: self.id,
                source,
            });
        }
        active_count(self.id, counts)
    }

    /// One cleanup round, never a promise based on the PID snapshot alone.
    /// `retain_helper` is used while the trusted helper owns the reservations;
    /// the external recovery owner may terminate the entire coalition instead.
    pub(super) fn terminate_round(&self, retain_helper: bool) -> Result<bool, CoalitionError> {
        if retain_helper && !self.helper.same_generation(&current_identity()?) {
            return Err(CoalitionError::WrongCleanupOwner);
        }
        for pid in all_processes()?.into_iter().filter(|pid| *pid > 0) {
            // A protected host process may be uninspectable. Skipping its PID
            // does not permit completion: the kernel count below must agree.
            let Ok(Some(before)) = ProcessIdentity::capture(pid) else {
                continue;
            };
            if retain_helper && before.same_generation(&self.helper) {
                continue;
            }
            if !matches!(membership(pid), Ok(id) if id == self.id) {
                continue;
            }
            let Ok(Some(after)) = ProcessIdentity::capture(pid) else {
                continue;
            };
            if !before.same_generation(&after) {
                continue;
            }
            // Membership is immutable. The kernel validates this generation
            // again atomically with delivery, so no numeric kill fallback.
            after
                .signal(libc::SIGKILL)
                .map_err(|source| CoalitionError::Signal { pid, source })?;
        }
        let active = self.active_tasks()?;
        if retain_helper {
            // This code is executing in the helper itself, so its own task
            // cannot already have exited. An external PID lookup cannot make
            // this promise: an exited process may still have a zombie record.
            Ok(active == 1)
        } else {
            Ok(active == 0)
        }
    }
}

fn current_identity() -> Result<ProcessIdentity, CoalitionError> {
    let pid = std::process::id() as libc::pid_t;
    ProcessIdentity::capture(pid)
        .map_err(|source| CoalitionError::Process { pid, source })?
        .ok_or(CoalitionError::HelperChanged)
}

fn generation_present(identity: &ProcessIdentity) -> Result<bool, CoalitionError> {
    ProcessIdentity::capture(identity.pid())
        .map(|current| current.is_some_and(|current| identity.same_generation(&current)))
        .map_err(|source| CoalitionError::Process {
            pid: identity.pid(),
            source,
        })
}

fn active_count(id: u64, counts: NativeAccounting) -> Result<u64, CoalitionError> {
    counts
        .started
        .checked_sub(counts.exited)
        .ok_or(CoalitionError::InconsistentAccounting {
            id,
            started: counts.started,
            exited: counts.exited,
        })
}

fn membership(pid: libc::pid_t) -> Result<u64, CoalitionError> {
    let mut info = NativeMembership::default();
    let expected = std::mem::size_of::<NativeMembership>() as libc::c_int;
    #[allow(unsafe_code)]
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDCOALITIONINFO,
            0,
            (&mut info as *mut NativeMembership).cast(),
            expected,
        )
    };
    if actual <= 0 {
        return Err(CoalitionError::Process {
            pid,
            source: io::Error::last_os_error(),
        });
    }
    if actual != expected {
        return Err(CoalitionError::RecordSize {
            pid,
            expected,
            actual,
        });
    }
    match info.ids[0] {
        0 => Err(CoalitionError::MissingMembership { pid }),
        id => Ok(id),
    }
}

fn all_processes() -> Result<Vec<libc::pid_t>, CoalitionError> {
    let mut pids = Vec::new();
    let mut capacity = INITIAL_PID_CAPACITY;
    loop {
        let bytes = snapshot_bytes(capacity)?;
        pids.try_reserve_exact(capacity - pids.len())
            .map_err(|source| CoalitionError::SnapshotAllocation { source })?;
        pids.resize(capacity, 0);
        #[allow(unsafe_code)]
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count < 0 {
            return Err(CoalitionError::Enumeration {
                source: io::Error::last_os_error(),
            });
        }
        let count = count as usize;
        if count < capacity {
            pids.truncate(count);
            return Ok(pids);
        }
        capacity = capacity
            .checked_mul(2)
            .ok_or(CoalitionError::SnapshotSize)?;
    }
}

fn snapshot_bytes(capacity: usize) -> Result<libc::c_int, CoalitionError> {
    capacity
        .checked_mul(std::mem::size_of::<libc::pid_t>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CoalitionError::SnapshotSize)
}

#[allow(unsafe_code)]
fn accounting_api() -> Result<ResourceUsage, CoalitionError> {
    RESOURCE_USAGE
        .get_or_init(|| {
            // libSystem stays loaded. Resolve optional SPI so unsupported hosts
            // receive a typed error rather than a dynamic-loader failure.
            let address = unsafe {
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"coalition_info_resource_usage".as_ptr(),
                )
            };
            if address.is_null() {
                None
            } else {
                // Apple libproc wrapper uses this exact C ABI; the output is a
                // caller-sized prefix of coalition_resource_usage.
                Some(unsafe { std::mem::transmute::<*mut libc::c_void, ResourceUsage>(address) })
            }
        })
        .ok_or(CoalitionError::AccountingUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use tempfile::TempDir;

    use super::{
        Coalition, CoalitionError, NativeAccounting, ProcessIdentity, active_count, snapshot_bytes,
    };

    const FIXTURE_ENV: &str = "CAGEFORGE_COALITION_UNIT_ROOT";
    const LEAF_ENV: &str = "CAGEFORGE_COALITION_UNIT_LEAF";
    const OWNER_ENV: &str = "CAGEFORGE_COALITION_UNIT_OWNER";
    const FIXTURE_TEST: &str = "process::coalition::tests::coalition_fixture";
    const DETACH: [&str; 3] = ["setsid", "setpgid", "spawn-group"];

    struct Family {
        coalition: Option<Coalition>,
        label: String,
        root: TempDir,
    }

    impl Family {
        fn start() -> Self {
            let root = TempDir::new().expect("family root");
            let label = format!(
                "cageforge-coalition-unit-{}-{}",
                std::process::id(),
                root.path()
                    .file_name()
                    .expect("unique root")
                    .to_string_lossy()
            );
            let mut family = Self {
                coalition: None,
                label,
                root,
            };
            let result = Command::new("/bin/launchctl")
                .args(["submit", "-l", &family.label, "--", "/usr/bin/env"])
                .arg(format!("{FIXTURE_ENV}={}", family.root.path().display()))
                .arg(format!("{OWNER_ENV}={}", std::process::id()))
                .arg(std::env::current_exe().expect("fixture executable"))
                .args(["--exact", FIXTURE_TEST, "--nocapture"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("launch user family");
            assert!(result.success(), "launchd fixture registration");
            let ready = family.root.path().join("ready");
            wait_until(|| ready.exists());
            let pid = fs::read_to_string(&ready)
                .expect("helper PID")
                .parse()
                .expect("native PID");
            let helper = ProcessIdentity::capture(pid)
                .expect("helper identity")
                .expect("helper alive");
            family.coalition = Some(
                Coalition::from_authenticated_helper(helper).expect("owned fixture coalition"),
            );
            family
        }

        fn boundary(&self) -> &Coalition {
            self.coalition.as_ref().expect("fixture boundary")
        }

        fn terminate(&self, retain_helper: bool) {
            if retain_helper {
                fs::write(self.root.path().join("cleanup"), b"terminate descendants")
                    .expect("request fixture self-cleanup");
                wait_until(|| self.root.path().join("descendants-gone").exists());
                return;
            }
            wait_until(|| {
                self.boundary()
                    .terminate_round(retain_helper)
                    .expect("cleanup round")
            });
        }
    }

    impl Drop for Family {
        fn drop(&mut self) {
            let _ = Command::new("/bin/launchctl")
                .args(["remove", &self.label])
                .output();
            if let Some(coalition) = &self.coalition {
                let deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < deadline {
                    if matches!(coalition.terminate_round(false), Ok(true)) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    #[test]
    fn coalition_fixture() {
        let Some(root) = std::env::var_os(FIXTURE_ENV).map(PathBuf::from) else {
            return;
        };
        if let Ok(mode) = std::env::var(LEAF_ENV) {
            #[allow(unsafe_code)]
            let result = unsafe {
                match mode.as_str() {
                    "setsid" => libc::setsid(),
                    "setpgid" => libc::setpgid(0, 0),
                    "spawn-group" => 0,
                    _ => panic!("invalid fixture mode"),
                }
            };
            assert!(result >= 0, "detach fixture");
            fs::write(root.join(mode), b"ready").expect("leaf readiness");
        } else {
            use std::os::unix::process::CommandExt;
            let parent = std::env::var(OWNER_ENV)
                .expect("fixture owner")
                .parse()
                .expect("owner PID");
            let parent = ProcessIdentity::capture(parent)
                .expect("owner identity")
                .expect("live owner");
            let coalition = Coalition::from_authenticated_parent(parent).expect("helper coalition");
            for mode in DETACH {
                let mut command =
                    Command::new(std::env::current_exe().expect("fixture executable"));
                command
                    .args(["--exact", FIXTURE_TEST, "--nocapture"])
                    .env(LEAF_ENV, mode)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                if mode == "spawn-group" {
                    command.process_group(0);
                }
                drop(command.spawn().expect("finite leaf"));
            }
            wait_until(|| DETACH.iter().all(|mode| root.join(mode).exists()));
            fs::write(root.join("ready.staging"), std::process::id().to_string())
                .expect("helper readiness");
            fs::rename(root.join("ready.staging"), root.join("ready")).expect("publish helper");
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut completed = false;
            while Instant::now() < deadline {
                if !completed
                    && root.join("cleanup").exists()
                    && coalition
                        .terminate_round(true)
                        .expect("helper cleanup round")
                {
                    fs::write(root.join("descendants-gone"), b"only helper remains")
                        .expect("publish completed self-cleanup");
                    completed = true;
                }
                thread::sleep(Duration::from_millis(5));
            }
            return;
        }
        thread::sleep(Duration::from_secs(20));
    }

    #[test]
    fn coalition_cleanup_preserves_the_helper_and_an_independent_family() {
        let first = Family::start();
        let second = Family::start();
        assert_eq!(first.boundary().active_tasks().expect("first count"), 4);
        assert_eq!(second.boundary().active_tasks().expect("second count"), 4);
        first.terminate(true);
        assert_eq!(first.boundary().active_tasks().expect("retained helper"), 1);
        assert_eq!(second.boundary().active_tasks().expect("neighbor count"), 4);
        first.terminate(false);
        assert_eq!(first.boundary().active_tasks().expect("empty family"), 0);
        second.terminate(false);
    }

    #[test]
    fn external_recovery_cannot_count_a_lost_helper_as_a_remaining_task() {
        let family = Family::start();
        family
            .boundary()
            .helper
            .signal(libc::SIGKILL)
            .expect("kill owned helper");
        wait_until(|| family.boundary().active_tasks().expect("remaining leaves") == 3);
        assert!(matches!(
            family.boundary().terminate_round(true),
            Err(CoalitionError::WrongCleanupOwner)
        ));
        family.terminate(false);
    }

    #[test]
    fn the_application_coalition_cannot_be_adopted_as_a_sandbox() {
        let own = ProcessIdentity::capture(std::process::id() as libc::pid_t)
            .expect("own identity")
            .expect("live caller");
        assert!(matches!(
            Coalition::from_authenticated_helper(own),
            Err(CoalitionError::SharedApplicationCoalition)
        ));
    }

    #[test]
    fn accounting_and_snapshot_arithmetic_fail_closed() {
        assert!(matches!(
            active_count(
                42,
                NativeAccounting {
                    started: 1,
                    exited: 2
                }
            ),
            Err(CoalitionError::InconsistentAccounting { .. })
        ));
        assert_eq!(
            active_count(
                42,
                NativeAccounting {
                    started: u64::MAX,
                    exited: u64::MAX
                }
            )
            .expect("equal counters"),
            0
        );
        assert!(matches!(
            snapshot_bytes(usize::MAX),
            Err(CoalitionError::SnapshotSize)
        ));
        assert!(matches!(
            snapshot_bytes(libc::c_int::MAX as usize),
            Err(CoalitionError::SnapshotSize)
        ));
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "coalition fixture deadline");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
