// SPDX-License-Identifier: Apache-2.0

//! Kernel process identity for individual lifecycle signals.

use std::io;
use std::sync::OnceLock;

use crate::error::MacosBackendError;

// Apple XNU bsd/sys/proc_info_private.h: proc_uniqidentifierinfo.
const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;
static SIGNAL_WITH_AUDIT_TOKEN: OnceLock<Option<SignalWithAuditToken>> = OnceLock::new();

pub(super) struct ProcessIdentity {
    pid: libc::pid_t,
    version: u32,
    #[cfg(test)]
    unique_id: u64,
}

#[repr(C)]
#[derive(Default)]
struct NativeProcessIdentity {
    uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    version: i32,
    reserved: u32,
    reserved_more: [u64; 2],
}

type SignalWithAuditToken = unsafe extern "C" fn(*mut [u32; 8], libc::c_int) -> libc::c_int;

impl ProcessIdentity {
    #[allow(unsafe_code)]
    pub(super) fn capture(pid: libc::pid_t) -> io::Result<Option<Self>> {
        if pid <= 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut native = NativeProcessIdentity::default();
        let size = std::mem::size_of::<NativeProcessIdentity>() as libc::c_int;
        // SAFETY: the selected flavor writes this exact fixed-layout structure.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut native as *mut NativeProcessIdentity).cast(),
                size,
            )
        };
        if written <= 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if written != size {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(Self {
            pid,
            version: native.version as u32,
            #[cfg(test)]
            unique_id: native.unique_id,
        }))
    }

    pub(super) fn signal(&self, signal: libc::c_int) -> io::Result<bool> {
        signal_identity(self.pid, self.version, signal)
    }

    #[cfg(test)]
    pub(super) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    #[cfg(test)]
    pub(super) fn same_generation(&self, other: &Self) -> bool {
        self.pid == other.pid && self.version == other.version && self.unique_id == other.unique_id
    }
}

pub(crate) fn verify_available() -> Result<(), MacosBackendError> {
    native_signal()
        .map(|_| ())
        .ok_or(MacosBackendError::VersionedProcessSignallingUnavailable)
}

#[allow(unsafe_code)]
fn native_signal() -> Option<SignalWithAuditToken> {
    *SIGNAL_WITH_AUDIT_TOKEN.get_or_init(|| {
        // Resolve the optional system API before spawning, rather than making
        // older macOS versions fail in the dynamic loader. libSystem remains
        // loaded for the process lifetime, so this function address is stable.
        let address =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
        if address.is_null() {
            None
        } else {
            // SAFETY: Apple libproc declares this symbol with this C ABI and
            // audit_token_t is exactly eight uint32_t words.
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, SignalWithAuditToken>(address) })
        }
    })
}

#[allow(unsafe_code)]
fn signal_identity(pid: libc::pid_t, version: u32, signal: libc::c_int) -> io::Result<bool> {
    let deliver = native_signal().ok_or(io::ErrorKind::Unsupported)?;
    let mut token = [0u32; 8];
    token[5] = pid as u32;
    token[7] = version;
    // SAFETY: XNU takes its own process reference, validates PID/version and
    // permissions, then delivers the signal while retaining that reference.
    // Unlike kill(2), this libproc wrapper returns an errno value, not -1.
    match unsafe { deliver(&mut token, signal) } {
        0 => Ok(true),
        libc::ESRCH => Ok(false),
        code => Err(io::Error::from_raw_os_error(code)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use super::ProcessIdentity;

    struct FixtureChild(Child);

    impl FixtureChild {
        fn start() -> Self {
            Self(
                Command::new("/bin/sleep")
                    .arg("20")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("finite signal fixture"),
            )
        }

        fn identity(&self) -> ProcessIdentity {
            ProcessIdentity::capture(self.0.id().try_into().expect("native child PID"))
                .expect("capture child identity")
                .expect("direct child exists")
        }
    }

    impl Drop for FixtureChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn stale_generation_cannot_signal_a_live_process_with_the_same_pid() {
        let mut child = FixtureChild::start();
        let current = child.identity();
        let stale = ProcessIdentity {
            pid: current.pid,
            version: current.version ^ 1,
            unique_id: current.unique_id,
        };
        // Deliberately reuse the *live owned child's* PID with another
        // generation, rather than depending on nondeterministic OS PID reuse.
        assert!(
            !stale.signal(libc::SIGKILL).expect("reject stale identity"),
            "a stale process identity delivered SIGKILL to the replacement"
        );
        assert!(child.0.try_wait().expect("child remains alive").is_none());
        assert!(
            current
                .signal(libc::SIGCONT)
                .expect("live identity remains valid")
        );
    }

    #[test]
    fn exact_generation_signal_terminates_only_its_owned_child() {
        let mut first = FixtureChild::start();
        let mut second = FixtureChild::start();
        assert!(
            first
                .identity()
                .signal(libc::SIGKILL)
                .expect("signal child")
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = first.0.try_wait().expect("collect child") {
                assert_eq!(status.signal(), Some(libc::SIGKILL));
                break;
            }
            assert!(Instant::now() < deadline, "signalled child remained active");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            second
                .0
                .try_wait()
                .expect("neighbor remains alive")
                .is_none()
        );
    }

    #[test]
    fn process_identity_rejects_nonpositive_pids() {
        for pid in [0, -1] {
            assert!(matches!(
                ProcessIdentity::capture(pid),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput
            ));
        }
    }
}
