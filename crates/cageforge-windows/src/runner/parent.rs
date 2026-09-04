// SPDX-License-Identifier: Apache-2.0

//! Trusted parent-side ownership for Windows runner resources.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, GetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_UILIMIT_ALL,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    TerminateProcess, WaitForSingleObject,
};

pub(crate) struct BoundaryTerminator {
    job: Mutex<Option<ParentJob>>,
    runner_process: OwnedHandle,
}

pub(crate) struct ParentJob {
    handle: OwnedHandle,
}

#[derive(Debug, Error)]
pub(crate) enum ParentBoundaryError {
    #[error(transparent)]
    Job(#[from] ParentJobError),
    #[error("failed to duplicate the runner process boundary: Windows error {code}")]
    RunnerDuplicate { code: u32 },
    #[error("Windows returned an invalid duplicated runner process handle")]
    InvalidRunnerDuplicate,
    #[error("the Windows process-boundary state lock was poisoned")]
    StatePoisoned,
    #[error("failed to terminate the authenticated command runner: Windows error {code}")]
    RunnerTerminate { code: u32 },
    #[error("waiting for the authenticated command runner failed: Windows error {code}")]
    RunnerWait { code: u32 },
    #[error("waiting for the authenticated command runner returned unexpected status {result:#x}")]
    RunnerWaitUnexpected { result: u32 },
    #[error("the authenticated command runner did not terminate within the safety deadline")]
    RunnerTerminationTimeout,
    #[error("failed to read the authenticated command-runner exit code: Windows error {code}")]
    RunnerExitCode { code: u32 },
    #[error("failed to open reported sandbox process {process_id}: Windows error {code}")]
    ChildProcessOpen { process_id: u32, code: u32 },
    #[error(
        "failed to verify Job Object membership for sandbox process {process_id}: Windows error {code}"
    )]
    ChildJobQuery { process_id: u32, code: u32 },
    #[error("reported sandbox process {process_id} is not a member of the parent-owned Job Object")]
    ChildOutsideJob { process_id: u32 },
}

#[derive(Debug, Error)]
pub(crate) enum ParentJobError {
    #[error("failed to create the Windows Job Object: Windows error {code}")]
    Create { code: u32 },
    #[error("failed to enable Job Object kill-on-close: Windows error {code}")]
    Configure { code: u32 },
    #[error("failed to enable Job Object user-interface isolation: Windows error {code}")]
    UiConfigure { code: u32 },
    #[error("failed to read back Job Object limits: Windows error {code}")]
    ReadBack { code: u32 },
    #[error("failed to read back Job Object user-interface isolation: Windows error {code}")]
    UiReadBack { code: u32 },
    #[error("Job Object read-back did not contain exactly kill-on-close")]
    LimitMismatch,
    #[error("Job Object read-back did not contain every user-interface isolation limit")]
    UiLimitMismatch,
    #[error(
        "failed to duplicate assign-only Job Object authority into the runner: Windows error {code}"
    )]
    DuplicateAssignOnly { code: u32 },
    #[error("Windows returned an invalid duplicated Job Object handle")]
    InvalidDuplicate,
    #[error("failed to terminate the complete Windows Job Object: Windows error {code}")]
    Terminate { code: u32 },
    #[error("failed to read active Windows Job Object processes: Windows error {code}")]
    ActiveProcessRead { code: u32 },
    #[error("Windows returned a truncated Job Object accounting record")]
    ActiveProcessReadBack,
    #[error(
        "the terminated Windows Job Object still contains {active_processes} active processes after the safety deadline"
    )]
    TerminationTimeout { active_processes: u32 },
}

#[derive(Debug, Error)]
pub(crate) enum RunnerHandleDuplicateError {
    #[error(
        "failed to duplicate a standard handle into the authenticated runner: Windows error {code}"
    )]
    Duplicate { code: u32 },
    #[error("Windows returned an invalid standard handle duplicated into the authenticated runner")]
    InvalidDuplicate,
}

impl BoundaryTerminator {
    #[allow(unsafe_code)]
    pub(crate) fn new(
        job: ParentJob,
        runner_process: &OwnedHandle,
    ) -> Result<Self, ParentBoundaryError> {
        let mut duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                runner_process.as_raw_handle() as _,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(ParentBoundaryError::RunnerDuplicate {
                code: unsafe { GetLastError() },
            });
        }
        if duplicate.is_null() {
            return Err(ParentBoundaryError::InvalidRunnerDuplicate);
        }
        Ok(Self {
            job: Mutex::new(Some(job)),
            runner_process: unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) },
        })
    }

    pub(crate) fn terminate(&self, exit_code: u32) -> Result<(), ParentBoundaryError> {
        let job_result = self.terminate_job(exit_code);
        let runner_result = self.terminate_runner(exit_code);
        job_result.and(runner_result)
    }

    #[allow(unsafe_code)]
    pub(crate) fn wait_runner(
        &self,
        timeout: Duration,
    ) -> Result<Option<u32>, ParentBoundaryError> {
        let maximum_timeout = u128::from(u32::MAX - 1);
        let timeout_millis = timeout.as_millis().min(maximum_timeout) as u32;
        let result = unsafe {
            WaitForSingleObject(self.runner_process.as_raw_handle() as _, timeout_millis)
        };
        match result {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut exit_code = 0;
                if unsafe {
                    GetExitCodeProcess(self.runner_process.as_raw_handle() as _, &mut exit_code)
                } == 0
                {
                    Err(ParentBoundaryError::RunnerExitCode {
                        code: unsafe { GetLastError() },
                    })
                } else {
                    Ok(Some(exit_code))
                }
            }
            WAIT_FAILED => Err(ParentBoundaryError::RunnerWait {
                code: unsafe { GetLastError() },
            }),
            result => Err(ParentBoundaryError::RunnerWaitUnexpected { result }),
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn duplicate_inheritable_handle(
        &self,
        source: RawHandle,
    ) -> Result<u64, RunnerHandleDuplicateError> {
        let mut duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source as _,
                self.runner_process.as_raw_handle() as _,
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(RunnerHandleDuplicateError::Duplicate {
                code: unsafe { GetLastError() },
            });
        }
        if duplicate.is_null() {
            return Err(RunnerHandleDuplicateError::InvalidDuplicate);
        }
        Ok(duplicate as usize as u64)
    }

    #[allow(unsafe_code)]
    pub(crate) fn verify_child_job_membership(
        &self,
        process_id: u32,
    ) -> Result<(), ParentBoundaryError> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(ParentBoundaryError::ChildProcessOpen {
                process_id,
                code: unsafe { GetLastError() },
            });
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
        let job = self
            .job
            .lock()
            .map_err(|_| ParentBoundaryError::StatePoisoned)?;
        let Some(job) = job.as_ref() else {
            return Err(ParentBoundaryError::ChildOutsideJob { process_id });
        };
        let mut assigned = 0;
        if unsafe {
            IsProcessInJob(
                process.as_raw_handle() as _,
                job.handle.as_raw_handle() as _,
                &mut assigned,
            )
        } == 0
        {
            return Err(ParentBoundaryError::ChildJobQuery {
                process_id,
                code: unsafe { GetLastError() },
            });
        }
        if assigned == 0 {
            Err(ParentBoundaryError::ChildOutsideJob { process_id })
        } else {
            Ok(())
        }
    }

    pub(crate) fn terminate_job(&self, exit_code: u32) -> Result<(), ParentBoundaryError> {
        let mut job = self
            .job
            .lock()
            .map_err(|_| ParentBoundaryError::StatePoisoned)?;
        let Some(current) = job.as_ref() else {
            return Ok(());
        };
        if let Err(error) = current.terminate(exit_code) {
            job.take();
            return Err(error.into());
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn terminate_runner(&self, exit_code: u32) -> Result<(), ParentBoundaryError> {
        if self.wait_runner(Duration::ZERO)?.is_some() {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.runner_process.as_raw_handle() as _, exit_code) } == 0 {
            return Err(ParentBoundaryError::RunnerTerminate {
                code: unsafe { GetLastError() },
            });
        }
        if self.wait_runner(Duration::from_secs(5))?.is_some() {
            Ok(())
        } else {
            Err(ParentBoundaryError::RunnerTerminationTimeout)
        }
    }
}

#[allow(unsafe_code)]
impl Drop for BoundaryTerminator {
    fn drop(&mut self) {
        let job = match self.job.get_mut() {
            Ok(job) => job,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(job) = job.take() {
            let _ = job.terminate(125);
        }
        if self.wait_runner(Duration::ZERO).ok().flatten().is_none() {
            unsafe {
                TerminateProcess(self.runner_process.as_raw_handle() as _, 125);
                WaitForSingleObject(self.runner_process.as_raw_handle() as _, 5_000);
            }
        }
    }
}

impl ParentJob {
    #[allow(unsafe_code)]
    pub(crate) fn new() -> Result<Self, ParentJobError> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(ParentJobError::Create {
                code: unsafe { GetLastError() },
            });
        }
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) },
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job.handle.as_raw_handle() as _,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(ParentJobError::Configure {
                code: unsafe { GetLastError() },
            });
        }
        let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_ALL,
        };
        if unsafe {
            SetInformationJobObject(
                job.handle.as_raw_handle() as _,
                JobObjectBasicUIRestrictions,
                (&raw const ui_limits).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        } == 0
        {
            return Err(ParentJobError::UiConfigure {
                code: unsafe { GetLastError() },
            });
        }
        job.verify_limits()?;
        Ok(job)
    }

    #[allow(unsafe_code)]
    pub(crate) fn duplicate_assign_only_into(
        &self,
        runner_process: *mut c_void,
    ) -> Result<u64, ParentJobError> {
        let mut duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle.as_raw_handle() as _,
                runner_process,
                &mut duplicate,
                JOB_OBJECT_ASSIGN_PROCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(ParentJobError::DuplicateAssignOnly {
                code: unsafe { GetLastError() },
            });
        }
        if duplicate.is_null() {
            return Err(ParentJobError::InvalidDuplicate);
        }
        Ok(duplicate as usize as u64)
    }

    #[allow(unsafe_code)]
    pub(crate) fn terminate(&self, exit_code: u32) -> Result<(), ParentJobError> {
        if unsafe { TerminateJobObject(self.handle.as_raw_handle() as _, exit_code) } == 0 {
            return Err(ParentJobError::Terminate {
                code: unsafe { GetLastError() },
            });
        }
        self.wait_until_empty(Duration::from_secs(5))
    }

    #[allow(unsafe_code)]
    fn verify_limits(&self) -> Result<(), ParentJobError> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned = 0;
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle() as _,
                JobObjectExtendedLimitInformation,
                (&raw mut limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(ParentJobError::ReadBack {
                code: unsafe { GetLastError() },
            });
        }
        if returned < size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
            || limits.BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        {
            return Err(ParentJobError::LimitMismatch);
        }
        let mut ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
        returned = 0;
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle() as _,
                JobObjectBasicUIRestrictions,
                (&raw mut ui_limits).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(ParentJobError::UiReadBack {
                code: unsafe { GetLastError() },
            });
        }
        if returned < size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32
            || ui_limits.UIRestrictionsClass != JOB_OBJECT_UILIMIT_ALL
        {
            return Err(ParentJobError::UiLimitMismatch);
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn active_processes(&self) -> Result<u32, ParentJobError> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0;
        if unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle() as _,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(ParentJobError::ActiveProcessRead {
                code: unsafe { GetLastError() },
            });
        }
        if returned < size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32 {
            return Err(ParentJobError::ActiveProcessReadBack);
        }
        Ok(accounting.ActiveProcesses)
    }

    fn wait_until_empty(&self, timeout: Duration) -> Result<(), ParentJobError> {
        let deadline = Instant::now() + timeout;
        loop {
            let active_processes = self.active_processes()?;
            if active_processes == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ParentJobError::TerminationTimeout { active_processes });
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}
