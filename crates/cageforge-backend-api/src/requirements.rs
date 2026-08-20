// SPDX-License-Identifier: Apache-2.0

use cageforge_command::{CommandRequest, EnvironmentBase, StdioMode, TimeoutPolicy};
use cageforge_policy::{
    AccessMode, DomainMode, FilesystemMode, FilesystemTarget, LocalNetworkAccess, NetworkMode,
    PathSelector, UnixSocketMode,
};
use cageforge_policy_compose::EffectiveSandbox;

use crate::{BackendCapabilities, BackendCapability};

pub(super) fn add_command_capabilities(
    required: &mut BackendCapabilities,
    command: &CommandRequest,
) {
    if command.working_directory().is_some() {
        required
            .capabilities
            .insert(BackendCapability::WorkingDirectory);
    }
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
    let requested = sandbox.filesystem().requested();
    let ceiling = sandbox.filesystem().ceiling();
    let mode = match (requested.mode(), ceiling.mode()) {
        (FilesystemMode::External, FilesystemMode::External) => FilesystemMode::External,
        (FilesystemMode::Restricted, _) | (_, FilesystemMode::Restricted) => {
            FilesystemMode::Restricted
        }
        (FilesystemMode::Unrestricted, FilesystemMode::Unrestricted) => {
            FilesystemMode::Unrestricted
        }
        (FilesystemMode::External, _) | (_, FilesystemMode::External) => {
            unreachable!("effective sandbox cannot contain mixed filesystem ownership")
        }
    };
    required.capabilities.insert(match mode {
        FilesystemMode::Restricted => BackendCapability::FilesystemRestricted,
        FilesystemMode::Unrestricted => BackendCapability::FilesystemUnrestricted,
        FilesystemMode::External => BackendCapability::FilesystemExternal,
    });
    if sandbox.workspace_roots().is_some() || sandbox.workspace_root_limit().is_some() {
        add_workspace_scope_capabilities(required);
    }
    if mode != FilesystemMode::Restricted {
        return;
    }
    let has_deny_glob = [requested, ceiling].iter().any(|policy| {
        policy.entries().iter().any(|rule| {
            matches!(rule.target(), FilesystemTarget::Glob(_)) && rule.access() == AccessMode::Deny
        })
    });
    if has_deny_glob {
        required
            .capabilities
            .insert(BackendCapability::FilesystemGlobScanDepth);
    }
    for policy in [requested, ceiling] {
        if !policy.protected_relative_paths().is_empty() {
            required
                .capabilities
                .insert(BackendCapability::FilesystemProtectedPaths);
        }
        for rule in policy.entries() {
            match rule.target() {
                FilesystemTarget::Scope(selector) => {
                    add_selector_capabilities(required, selector);
                    required
                        .capabilities
                        .insert(BackendCapability::FilesystemMissingPathBehavior);
                }
                FilesystemTarget::Glob(pattern) => {
                    required
                        .capabilities
                        .insert(BackendCapability::FilesystemGlobs);
                    if pattern.is_absolute() {
                        required
                            .capabilities
                            .insert(BackendCapability::FilesystemScopes);
                        required
                            .capabilities
                            .insert(BackendCapability::FilesystemAbsoluteScopes);
                    } else {
                        add_workspace_scope_capabilities(required);
                    }
                }
            }
            for selector in rule.read_only_subpaths() {
                add_selector_capabilities(required, selector);
            }
            if !rule.read_only_subpaths().is_empty() {
                required
                    .capabilities
                    .insert(BackendCapability::FilesystemReadOnlySubpaths);
            }
        }
    }
}

fn add_workspace_scope_capabilities(required: &mut BackendCapabilities) {
    required
        .capabilities
        .insert(BackendCapability::FilesystemScopes);
    required
        .capabilities
        .insert(BackendCapability::FilesystemWorkspaceScopes);
}

fn add_selector_capabilities(required: &mut BackendCapabilities, selector: &PathSelector) {
    required
        .capabilities
        .insert(BackendCapability::FilesystemScopes);
    let capability = if selector.is_absolute_scope() {
        BackendCapability::FilesystemAbsoluteScopes
    } else if selector.is_workspace_scope() {
        BackendCapability::FilesystemWorkspaceScopes
    } else if selector.is_root_scope() {
        BackendCapability::FilesystemRootScopes
    } else if selector.is_minimal_scope() {
        BackendCapability::FilesystemMinimalScopes
    } else if selector.is_tmpdir_scope() {
        BackendCapability::FilesystemTmpdirScopes
    } else if selector.is_slash_tmp_scope() {
        BackendCapability::FilesystemSlashTmpScopes
    } else {
        unreachable!("PathSelector has an unrecognized scope kind")
    };
    required.capabilities.insert(capability);
}

pub(super) fn add_network_capabilities(
    required: &mut BackendCapabilities,
    sandbox: &EffectiveSandbox,
) {
    let requested = sandbox.network().requested();
    let ceiling = sandbox.network().ceiling();
    let mode = match (requested.mode(), ceiling.mode()) {
        (NetworkMode::External, NetworkMode::External) => NetworkMode::External,
        (NetworkMode::Disabled, _) | (_, NetworkMode::Disabled) => NetworkMode::Disabled,
        (NetworkMode::Enabled, NetworkMode::Enabled) => NetworkMode::Enabled,
        (NetworkMode::External, _) | (_, NetworkMode::External) => {
            unreachable!("effective sandbox cannot contain mixed network ownership")
        }
    };
    required.capabilities.insert(match mode {
        NetworkMode::Disabled => BackendCapability::NetworkDisabled,
        NetworkMode::Enabled => BackendCapability::NetworkEnabled,
        NetworkMode::External => BackendCapability::NetworkExternal,
    });
    if mode != NetworkMode::Enabled {
        return;
    }
    required
        .capabilities
        .insert(BackendCapability::NetworkResolvedTargets);
    for policy in [requested, ceiling] {
        if !policy.domains().is_empty() || policy.domain_mode() != DomainMode::Enabled {
            required
                .capabilities
                .insert(BackendCapability::NetworkDomainRules);
        }
        if policy.local_network_access() == LocalNetworkAccess::Deny {
            required
                .capabilities
                .insert(BackendCapability::NetworkLocalAddressRestrictions);
        }
        if !policy.unix_sockets().is_empty()
            || policy.unix_socket_mode() != UnixSocketMode::Disabled
        {
            required
                .capabilities
                .insert(BackendCapability::NetworkUnixSockets);
        }
    }
}

pub(super) fn add_environment_capabilities(
    required: &mut BackendCapabilities,
    sandbox: &EffectiveSandbox,
) {
    required
        .capabilities
        .insert(match sandbox.environment().base() {
            EnvironmentBase::All => BackendCapability::EnvironmentAll,
            EnvironmentBase::Core => BackendCapability::EnvironmentCore,
            EnvironmentBase::None => BackendCapability::EnvironmentNone,
        });
    if !sandbox.environment().requested().filters().is_empty()
        || !sandbox.environment().ceiling().filters().is_empty()
    {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentFilters);
    }
    if !sandbox.environment().requested().overrides().is_empty()
        || !sandbox.environment().ceiling().overrides().is_empty()
    {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentOverrides);
    }
}
