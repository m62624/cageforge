// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

/// Routing for one standard process stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// Connect the child stream to the launcher process's corresponding
    /// standard stream.
    Inherit,
    /// Connect the child stream to the platform's null device.
    Null,
    /// Ask the backend to create a pipe for the caller.
    Pipe,
}

/// Portable routing choices for stdin, stdout, and stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioSpec {
    stdin: StdioMode,
    stdout: StdioMode,
    stderr: StdioMode,
}

impl StdioSpec {
    /// Creates explicit routing choices for all three standard streams.
    pub const fn new(stdin: StdioMode, stdout: StdioMode, stderr: StdioMode) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
        }
    }

    /// Creates the non-interactive default: closed stdin and captured output.
    pub const fn captured() -> Self {
        Self::new(StdioMode::Null, StdioMode::Pipe, StdioMode::Pipe)
    }

    /// Creates a request that inherits all three standard streams.
    pub const fn inherited() -> Self {
        Self::new(StdioMode::Inherit, StdioMode::Inherit, StdioMode::Inherit)
    }

    /// Replaces stdin routing.
    pub const fn with_stdin(mut self, mode: StdioMode) -> Self {
        self.stdin = mode;
        self
    }

    /// Replaces stdout routing.
    pub const fn with_stdout(mut self, mode: StdioMode) -> Self {
        self.stdout = mode;
        self
    }

    /// Replaces stderr routing.
    pub const fn with_stderr(mut self, mode: StdioMode) -> Self {
        self.stderr = mode;
        self
    }

    /// Returns stdin routing.
    pub const fn stdin(&self) -> StdioMode {
        self.stdin
    }

    /// Returns stdout routing.
    pub const fn stdout(&self) -> StdioMode {
        self.stdout
    }

    /// Returns stderr routing.
    pub const fn stderr(&self) -> StdioMode {
        self.stderr
    }
}

impl Default for StdioSpec {
    fn default() -> Self {
        Self::captured()
    }
}
