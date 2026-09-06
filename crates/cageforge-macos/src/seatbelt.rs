// SPDX-License-Identifier: Apache-2.0

//! Re-authored Seatbelt profile construction.

use std::path::{Path, PathBuf};

use crate::error::SeatbeltProfileError;
use crate::filesystem::MacosFilesystemPlan;
use crate::network::{MacosNetworkPlan, MacosUnixSocketPlan};

const SEATBELT_BASE_POLICY: &str = r#"
(version 1)
(deny default)

; Process descendants inherit the same closed-by-default profile.
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))

; Minimal runtime access needed by ordinary command-line programs.
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/System"))
(allow file-read-data (subpath "/bin"))
(allow file-read-metadata (subpath "/bin"))
(allow file-read-data (subpath "/sbin"))
(allow file-read-metadata (subpath "/sbin"))
(allow file-read-data (subpath "/usr/bin"))
(allow file-read-metadata (subpath "/usr/bin"))
(allow file-read-data (subpath "/usr/sbin"))
(allow file-read-metadata (subpath "/usr/sbin"))
(allow file-read-data (subpath "/usr/libexec"))
(allow file-read-metadata (subpath "/usr/libexec"))
(allow file-read* (subpath "/Library/Preferences"))
(allow file-read* (subpath "/private/etc"))
(allow file-read* (subpath "/etc"))
(allow file-read* file-test-existence (subpath "/private/var/db"))
(allow file-read-metadata (subpath "/private/var"))
(allow file-read-metadata (subpath "/var"))
(allow file-read* file-test-existence file-write* (subpath "/tmp"))
(allow file-read* file-test-existence file-write* (subpath "/private/tmp"))
(allow file-read* file-test-existence file-write* (subpath "/var/tmp"))
(allow file-read* file-test-existence file-write* (subpath "/private/var/tmp"))
(allow file-read-metadata file-test-existence
  (literal "/etc")
  (literal "/tmp")
  (literal "/var")
  (literal "/private/etc/localtime"))
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/zero"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))
(allow file-write-data (literal "/dev/null"))
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow pseudo-tty)

; Read-only process and user-service queries used by standard runtimes.
(allow sysctl-read
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.machine")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.version")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid."))
(allow user-preference-read)
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data)
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.cfprefsd.agent")
  (local-name "com.apple.cfprefsd.agent"))
"#;

const SEATBELT_NETWORK_SERVICE_POLICY: &str = r#"
; Safe local services needed for system name and trust configuration.
(allow system-socket
  (require-all
    (socket-domain AF_SYSTEM)
    (socket-protocol 2)))
(allow mach-lookup
  (global-name "com.apple.networkd")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.SystemConfiguration.configd"))
(allow sysctl-read (sysctl-name-regex #"^net.routetable"))
"#;

/// Complete policy text and safe path definitions for one launch.
#[derive(Debug)]
pub(crate) struct SeatbeltProfile {
    policy: String,
    definitions: Vec<SeatbeltDefinition>,
}

/// One trusted path passed to Seatbelt as a separate `-D` argument.
#[derive(Debug)]
pub(crate) struct SeatbeltDefinition {
    name: String,
    value: PathBuf,
}

impl SeatbeltProfile {
    /// Builds a closed-by-default profile from the complete native plans.
    pub(crate) fn build(
        filesystem: &MacosFilesystemPlan,
        network: &MacosNetworkPlan,
    ) -> Result<Self, SeatbeltProfileError> {
        let mut builder = ProfileBuilder::new();
        builder.push_raw(SEATBELT_BASE_POLICY);
        builder.add_filesystem(filesystem);
        builder.add_network(network)?;
        Ok(builder.finish())
    }

    pub(crate) fn policy(&self) -> &str {
        &self.policy
    }

    pub(crate) fn definitions(&self) -> &[SeatbeltDefinition] {
        &self.definitions
    }
}

impl SeatbeltDefinition {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn value(&self) -> &Path {
        &self.value
    }
}

struct ProfileBuilder {
    policy: String,
    definitions: Vec<SeatbeltDefinition>,
}

impl ProfileBuilder {
    fn new() -> Self {
        Self {
            policy: String::new(),
            definitions: Vec::new(),
        }
    }

    fn push_raw(&mut self, value: &str) {
        self.policy.push_str(value);
        self.policy.push('\n');
    }

    fn add_filesystem(&mut self, plan: &MacosFilesystemPlan) {
        if plan.unrestricted() {
            self.policy.push_str("\n(allow file-read*)\n");
            self.policy
                .push_str("(allow file-write* (regex #\"^/\"))\n");
        } else {
            self.add_roots("file-read*", "READ_ROOT", plan.read_roots());
            self.add_roots("file-write*", "WRITE_ROOT", plan.write_roots());
        }
        for (index, path) in plan.denied_paths().iter().enumerate() {
            let name = format!("DENIED_PATH_{index}");
            self.add_definition(name.clone(), path.clone());
            self.policy
                .push_str(&format!("(deny file-read* (subpath (param \"{name}\")))\n"));
            self.policy.push_str(&format!(
                "(deny file-write* (subpath (param \"{name}\")))\n"
            ));
        }
        for pattern in plan.denied_globs() {
            let regex = glob_to_seatbelt_regex(pattern);
            self.policy.push_str(&format!(
                "(deny file-read* (regex #\"{}\"))\n",
                escape_profile_string(&regex)
            ));
            self.policy.push_str(&format!(
                "(deny file-write* (regex #\"{}\"))\n",
                escape_profile_string(&regex)
            ));
        }
    }

    fn add_roots(&mut self, action: &str, prefix: &str, roots: &[PathBuf]) {
        if roots.is_empty() {
            return;
        }
        self.policy.push_str(&format!("\n(allow {action}\n"));
        for (index, path) in roots.iter().enumerate() {
            let name = format!("{prefix}_{index}");
            self.add_definition(name.clone(), path.clone());
            self.policy
                .push_str(&format!("  (subpath (param \"{name}\"))\n"));
        }
        self.policy.push_str(")\n");
    }

    fn add_network(&mut self, network: &MacosNetworkPlan) -> Result<(), SeatbeltProfileError> {
        match network {
            MacosNetworkPlan::Disabled { unix } => {
                self.add_unix_socket_rules(unix, false);
            }
            MacosNetworkPlan::Direct { unix } => {
                self.policy
                    .push_str("\n(allow network-outbound)\n(allow network-inbound)\n");
                self.policy.push_str(SEATBELT_NETWORK_SERVICE_POLICY);
                self.add_unix_socket_rules(unix, true);
            }
            MacosNetworkPlan::Proxy { ingress_port, unix } => {
                let Some(ingress_port) = ingress_port else {
                    return Err(SeatbeltProfileError::InvalidFragment {
                        fragment: "proxy ingress port is missing",
                    });
                };
                self.policy.push_str(&format!(
                    "\n(allow network-outbound (remote ip \"localhost:{ingress_port}\"))\n"
                ));
                self.policy.push_str(SEATBELT_NETWORK_SERVICE_POLICY);
                self.add_unix_socket_rules(unix, true);
            }
        }
        Ok(())
    }

    fn add_unix_socket_rules(&mut self, plan: &MacosUnixSocketPlan, enabled: bool) {
        if !enabled || (!plan.allow_all() && plan.allowed().is_empty()) {
            return;
        }
        self.policy
            .push_str("\n(allow system-socket (socket-domain AF_UNIX))\n");
        if plan.allow_all() {
            self.policy
                .push_str("(allow network-bind (local unix-socket))\n");
            self.policy
                .push_str("(allow network-outbound (remote unix-socket))\n");
        }
        for (index, path) in plan.allowed().iter().enumerate() {
            let name = format!("UNIX_SOCKET_PATH_{index}");
            self.add_definition(name.clone(), path.clone());
            self.policy.push_str(&format!(
                "(allow network-bind (local unix-socket (subpath (param \"{name}\"))))\n"
            ));
            self.policy.push_str(&format!(
                "(allow network-outbound (remote unix-socket (subpath (param \"{name}\"))))\n"
            ));
        }
        for (index, path) in plan.denied().iter().enumerate() {
            let name = format!("DENIED_UNIX_SOCKET_PATH_{index}");
            self.add_definition(name.clone(), path.clone());
            self.policy.push_str(&format!(
                "(deny network-bind (local unix-socket (subpath (param \"{name}\"))))\n"
            ));
            self.policy.push_str(&format!(
                "(deny network-outbound (remote unix-socket (subpath (param \"{name}\"))))\n"
            ));
        }
    }

    fn add_definition(&mut self, name: String, value: PathBuf) {
        self.definitions.push(SeatbeltDefinition { name, value });
    }

    fn finish(self) -> SeatbeltProfile {
        SeatbeltProfile {
            policy: self.policy,
            definitions: self.definitions,
        }
    }
}

fn glob_to_seatbelt_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    regex.push_str("(?:.*/)?");
                } else {
                    regex.push_str(".*");
                }
            }
            '*' => regex.push_str("[^/]*"),
            '?' => regex.push_str("[^/]"),
            '[' => {
                regex.push('[');
                if chars.peek() == Some(&'!') {
                    chars.next();
                    regex.push('^');
                }
                for class_character in chars.by_ref() {
                    regex.push(class_character);
                    if class_character == ']' {
                        break;
                    }
                }
            }
            character => push_regex_literal(&mut regex, character),
        }
    }
    if !pattern_has_glob_meta(pattern) {
        regex.push_str("(/.*)?");
    }
    regex.push('$');
    regex
}

fn pattern_has_glob_meta(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|character| matches!(character, '*' | '?' | '['))
}

fn push_regex_literal(regex: &mut String, character: char) {
    if matches!(
        character,
        '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '\\'
    ) {
        regex.push('\\');
    }
    regex.push(character);
}

fn escape_profile_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => ['\\', '\\'].into_iter().collect::<Vec<_>>(),
            '"' => ['\\', '"'].into_iter().collect::<Vec<_>>(),
            character => [character].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}
