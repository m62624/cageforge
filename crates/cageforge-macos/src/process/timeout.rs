// SPDX-License-Identifier: Apache-2.0

//! Independent command deadlines synchronized with collection of the leader.

use std::{
    process::{Child, ExitStatus},
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
};
#[cfg(test)]
use std::{thread, time::Instant};

use crate::error::MacosBackendError;

#[cfg(test)]
const TIMEOUT_THREAD_NAME: &str = "cageforge-macos-timeout";

pub(super) struct TimeoutWatchdog {
    state: Arc<Mutex<TimeoutState>>,
    cancel: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

struct TimeoutState {
    leader_unreaped: bool,
    timed_out: bool,
    error: Option<MacosBackendError>,
}

impl TimeoutWatchdog {
    #[cfg(test)]
    pub(super) fn start(
        process_group_id: u32,
        deadline: Instant,
    ) -> Result<Self, MacosBackendError> {
        let state = Arc::new(Mutex::new(TimeoutState {
            leader_unreaped: true,
            timed_out: false,
            error: None,
        }));
        let worker_state = Arc::clone(&state);
        let (cancel, control) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(TIMEOUT_THREAD_NAME.to_owned())
            .spawn(move || {
                if matches!(
                    control.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    expire(&worker_state, process_group_id);
                }
            })
            .map_err(|source| MacosBackendError::TimeoutWatchdogSetup { source })?;
        Ok(Self {
            state,
            cancel: Some(cancel),
            thread: Some(thread),
        })
    }

    pub(super) fn try_wait(
        &self,
        child: &mut Child,
    ) -> Result<Option<ExitStatus>, MacosBackendError> {
        // Normal polling checks health first. Cleanup must nevertheless be
        // able to collect the child after a worker panic poisoned this lock.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let status = child
            .try_wait()
            .map_err(|source| MacosBackendError::ProcessWait { source })?;
        if status.is_some() {
            state.leader_unreaped = false;
        }
        Ok(status)
    }

    pub(super) fn timed_out(&self) -> Result<bool, MacosBackendError> {
        self.state
            .lock()
            .map(|state| state.timed_out)
            .map_err(|_| MacosBackendError::TimeoutWatchdogLockPoisoned)
    }

    pub(super) fn check_health(&self) -> Result<(), MacosBackendError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MacosBackendError::TimeoutWatchdogLockPoisoned)?;
        match state.error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn shutdown(&mut self) -> Result<(), MacosBackendError> {
        // Recover a poisoned guard for cancellation so Drop can still join.
        // Never join while holding the guard needed by the worker.
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.leader_unreaped = false;
        }
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Err(MacosBackendError::TimeoutWatchdogPanicked);
        }
        let poisoned = self.state.is_poisoned();
        self.state.clear_poison();
        self.check_health()?;
        if poisoned {
            Err(MacosBackendError::TimeoutWatchdogLockPoisoned)
        } else {
            Ok(())
        }
    }
}

impl Drop for TimeoutWatchdog {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
fn expire(state: &Mutex<TimeoutState>, process_group_id: u32) {
    // Collection takes the same guard and disarms signalling before releasing
    // it. An unreaped direct child reserves the numeric PID/PGID even when it
    // has already exited.
    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
    if state.leader_unreaped {
        state.timed_out = true;
        state.error = super::terminate_process_group_if_present(process_group_id).err();
    }
}

#[cfg(test)]
mod tests {
    use std::{process::Command, sync::Arc, time::Duration};

    use super::{MacosBackendError, TimeoutWatchdog, expire};

    #[test]
    fn collecting_the_leader_disarms_a_late_timeout_callback() {
        let mut child = Command::new("/usr/bin/true").spawn().expect("fixture");
        // An invalid group is deliberate: if expiry attempts to signal after
        // collection it records ProcessGroupIdInvalid, without risking a host
        // process. Run the real callback directly to make the race ordering
        // deterministic instead of depending on thread scheduling.
        let mut watchdog =
            TimeoutWatchdog::start(0, std::time::Instant::now() + Duration::from_secs(60))
                .expect("watchdog");
        while watchdog
            .try_wait(&mut child)
            .expect("poll fixture")
            .is_none()
        {
            std::thread::yield_now();
        }
        expire(&watchdog.state, 0);
        assert!(!watchdog.timed_out().expect("timeout result"));
        watchdog.check_health().expect("no signal after collection");
        watchdog.shutdown().expect("cancel waiting thread");
    }

    #[test]
    fn watchdog_records_a_signal_error_without_losing_timeout_state() {
        let mut watchdog =
            TimeoutWatchdog::start(0, std::time::Instant::now() + Duration::from_secs(60))
                .expect("watchdog");
        expire(&watchdog.state, 0);
        assert!(watchdog.timed_out().expect("timeout result"));
        assert!(matches!(
            watchdog.check_health(),
            Err(MacosBackendError::ProcessGroupIdInvalid)
        ));
        watchdog.shutdown().expect("cancel after signal failure");
    }

    #[test]
    fn poisoned_watchdog_can_be_cancelled_and_cleanup_retried() {
        let mut watchdog =
            TimeoutWatchdog::start(0, std::time::Instant::now() + Duration::from_secs(60))
                .expect("watchdog");
        let state = Arc::clone(&watchdog.state);
        let poisoned = std::panic::catch_unwind(move || {
            let _guard = state.lock().expect("initial lock");
            panic!("injected watchdog panic");
        });
        assert!(poisoned.is_err());
        assert!(matches!(
            watchdog.check_health(),
            Err(MacosBackendError::TimeoutWatchdogLockPoisoned)
        ));
        assert!(matches!(
            watchdog.shutdown(),
            Err(MacosBackendError::TimeoutWatchdogLockPoisoned)
        ));
        assert!(watchdog.thread.is_none());
        watchdog.shutdown().expect("idempotent cleanup retry");
    }
}
