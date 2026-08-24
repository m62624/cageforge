// SPDX-License-Identifier: Apache-2.0

use cageforge_command::{CommandRequest, EnvironmentBase, StdioMode, TimeoutPolicy};
use cageforge_policy::{FilesystemMode, NetworkMode};
use cageforge_policy_compose::EffectiveSandbox;

use crate::{BackendCapabilities, BackendCapability};

pub(super) fn add_command_capabilities(
    required: &mut BackendCapabilities,
    command: &CommandRequest,
) {
    // Every launched process has a working directory, even when the command
    // does not override it. Preflight must therefore receive and validate the
    // runtime current directory instead of allowing the backend to inherit an
    // unchecked parent directory.
    required
        .capabilities
        .insert(BackendCapability::WorkingDirectory);
    for mode in [
        command.stdio().stdin(),
        command.stdio().stdout(),
        command.stdio().stderr(),
    ] {
        required.capabilities.insert(match mode {
            StdioMode::Inherit => BackendCapability::StdioInherit,
            StdioMode::Null => BackendCapability::StdioNull,
            StdioMode::Pipe => BackendCapability::StdioPipe,
        });
    }
    required
        .capabilities
        .insert(match command.timeout_policy() {
            TimeoutPolicy::BackendDefault => BackendCapability::TimeoutBackendDefault,
            TimeoutPolicy::Limit(_) => BackendCapability::TimeoutLimit,
            TimeoutPolicy::Disabled => BackendCapability::TimeoutDisabled,
        });
}

pub(super) fn add_filesystem_capabilities(
    required: &mut BackendCapabilities,
    sandbox: &EffectiveSandbox,
) {
    let requirements = sandbox.filesystem().requirements();
    let mode = requirements.mode();
    required.capabilities.insert(match mode {
        FilesystemMode::Restricted => BackendCapability::FilesystemRestricted,
        FilesystemMode::Unrestricted => BackendCapability::FilesystemUnrestricted,
        FilesystemMode::External => BackendCapability::FilesystemExternal,
    });
    if sandbox.workspace_roots().is_some() || sandbox.workspace_root_limit().is_some() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemScopes);
        required
            .capabilities
            .insert(BackendCapability::FilesystemWorkspaceScopes);
    }
    if mode != FilesystemMode::Restricted {
        return;
    }
    if requirements.glob_scan_depth() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemGlobScanDepth);
    }
    if requirements.protected_paths() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemProtectedPaths);
    }
    if requirements.scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemScopes);
    }
    if requirements.absolute_scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemAbsoluteScopes);
    }
    if requirements.workspace_scopes() || sandbox.workspace_roots().is_some() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemWorkspaceScopes);
    }
    if requirements.root_scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemRootScopes);
    }
    if requirements.minimal_scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemMinimalScopes);
    }
    if requirements.tmpdir_scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemTmpdirScopes);
    }
    if requirements.slash_tmp_scopes() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemSlashTmpScopes);
    }
    if requirements.globs() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemGlobs);
    }
    if requirements.read_only_subpaths() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemReadOnlySubpaths);
    }
    if requirements.missing_path_behavior() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemMissingPathBehavior);
    }
}

pub(super) fn add_network_capabilities(
    required: &mut BackendCapabilities,
    sandbox: &EffectiveSandbox,
) {
    let requirements = sandbox.network().requirements();
    let mode = requirements.mode();
    required.capabilities.insert(match mode {
        NetworkMode::Disabled => BackendCapability::NetworkDisabled,
        NetworkMode::Enabled => BackendCapability::NetworkEnabled,
        NetworkMode::External => BackendCapability::NetworkExternal,
    });
    if mode != NetworkMode::Enabled {
        return;
    }
    if requirements.resolved_targets() {
        required
            .capabilities
            .insert(BackendCapability::NetworkResolvedTargets);
    }
    if requirements.domain_rules() {
        required
            .capabilities
            .insert(BackendCapability::NetworkDomainRules);
    }
    if requirements.local_address_restrictions() {
        required
            .capabilities
            .insert(BackendCapability::NetworkLocalAddressRestrictions);
    }
    if requirements.unix_socket_isolation() {
        required
            .capabilities
            .insert(BackendCapability::NetworkUnixSocketIsolation);
    }
    if requirements.unix_socket_rules() {
        required
            .capabilities
            .insert(BackendCapability::NetworkUnixSocketRules);
    }
}

pub(super) fn add_environment_capabilities(
    required: &mut BackendCapabilities,
    sandbox: &EffectiveSandbox,
) {
    let requirements = sandbox.environment().requirements();
    required.capabilities.insert(match requirements.base() {
        EnvironmentBase::All => BackendCapability::EnvironmentAll,
        EnvironmentBase::Core => BackendCapability::EnvironmentCore,
        EnvironmentBase::None => BackendCapability::EnvironmentNone,
    });
    if requirements.filters() {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentFilters);
    }
    if requirements.overrides() {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentOverrides);
    }
}
