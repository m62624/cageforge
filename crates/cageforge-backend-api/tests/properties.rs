use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::SandboxPolicy;
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use proptest::prelude::*;

struct PropertyBackend {
    capabilities: BackendCapabilities,
}

impl SandboxBackend for PropertyBackend {
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
            .prepare_for(&backend)
            .is_err());
    }
}
