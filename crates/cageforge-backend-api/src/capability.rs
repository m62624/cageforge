// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::BackendCapability;

impl fmt::Display for BackendCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::CommandExecution => "command execution",
            Self::WorkingDirectory => "working-directory resolution",
            Self::StdioInherit => "inherited standard streams",
            Self::StdioNull => "null standard streams",
            Self::StdioPipe => "piped standard streams",
            Self::TimeoutBackendDefault => "backend-default timeout",
            Self::TimeoutLimit => "explicit timeout limits",
            Self::TimeoutDisabled => "disabled automatic timeouts",
            Self::FilesystemRestricted => "restricted filesystem enforcement",
            Self::FilesystemUnrestricted => "unrestricted filesystem execution",
            Self::FilesystemExternal => "external filesystem enforcement",
            Self::FilesystemScopes => "filesystem scope resolution, including workspace roots",
            Self::FilesystemAbsoluteScopes => "absolute filesystem scope resolution",
            Self::FilesystemWorkspaceScopes => "workspace-root filesystem scope resolution",
            Self::FilesystemRootScopes => "system-root filesystem scope resolution",
            Self::FilesystemMinimalScopes => "platform-minimal filesystem scope resolution",
            Self::FilesystemTmpdirScopes => "temporary-directory filesystem scope resolution",
            Self::FilesystemConventionalTemporaryScopes => {
                "conventional temporary filesystem scope resolution"
            }
            Self::FilesystemGlobs => "filesystem deny-glob matching",
            Self::FilesystemGlobScanDepth => {
                "filesystem glob scan-depth semantics, including unbounded scans"
            }
            Self::FilesystemReadOnlySubpaths => "filesystem read-only subpaths",
            Self::FilesystemMissingPathBehavior => {
                "filesystem missing-path behavior (error or skip)"
            }
            Self::FilesystemProtectedPaths => "filesystem protected paths such as .git",
            Self::NetworkDisabled => "disabled network enforcement",
            Self::NetworkEnabled => "local network enforcement",
            Self::NetworkExternal => "external network enforcement",
            Self::NetworkDomainRules => "network domain rules",
            Self::NetworkLocalAddressRestrictions => {
                "network non-public and special-purpose address restrictions"
            }
            Self::NetworkResolvedTargets => "exact resolved network targets",
            Self::NetworkLocalIpcIsolation => "pathname local-IPC isolation",
            Self::NetworkLocalIpcRules => "per-path local-IPC rules",
            Self::EnvironmentAll => "all inherited environment variables",
            Self::EnvironmentCore => "backend-selected core environment variables",
            Self::EnvironmentNone => "an empty inherited environment",
            Self::EnvironmentFilters => "environment include and exclude filters",
            Self::EnvironmentOverrides => "environment set and remove overrides",
        };
        formatter.write_str(description)
    }
}
