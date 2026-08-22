use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(windows)]
fn native_path(path: &str) -> PathBuf {
    let suffix = path.strip_prefix('/').unwrap_or(path).replace('/', "\\");
    PathBuf::from(format!(r"C:\{suffix}"))
}

#[cfg(not(windows))]
fn native_path(path: &str) -> PathBuf {
    PathBuf::from(path)
}

struct PropertyBackend {
    capabilities: BackendCapabilities,
}

impl SandboxBackend for PropertyBackend {
    fn identity(&self) -> &BackendIdentity {
        static IDENTITY: OnceLock<BackendIdentity> = OnceLock::new();
        IDENTITY.get_or_init(BackendIdentity::new)
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }
}

fn request() -> (CommandRequest, cageforge_policy_compose::EffectiveSandbox) {
    let requested = SandboxPolicy::read_only();
    let environment = EnvironmentSpec::inherit_core();
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let sandbox = compose(CompositionRequest::new(&requested, &environment, &ceiling)).unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap());
    (command, sandbox)
}

proptest! {
    #[test]
    fn missing_capability_never_prepares_the_request(index in 0usize..3) {
        let (command, sandbox) = request();
        let missing = [
            BackendCapability::CommandExecution,
            BackendCapability::FilesystemRestricted,
            BackendCapability::NetworkDisabled,
        ][index];
        let capabilities = BackendCapabilities::from_capabilities(
            BackendRequest::new(&command, &sandbox)
                .required_capabilities()
                .iter()
                .copied()
                .filter(|capability| *capability != missing),
        );
        let backend = PropertyBackend { capabilities };
        prop_assert!(BackendRequest::new(&command, &sandbox)
            .prepare_for(
                &backend,
                &PathResolutionContext::new()
                    .with_workspace_root(native_path("/workspace"))
                    .expect("valid workspace root")
                    .with_current_directory(native_path("/workspace"))
                    .expect("valid current directory"),
            )
            .is_err());
    }
}
