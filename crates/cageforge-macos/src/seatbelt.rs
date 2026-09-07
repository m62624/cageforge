// SPDX-License-Identifier: Apache-2.0

//! Re-authored Seatbelt profile construction.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use cageforge_path::is_within;

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

; Minimal runtime access needed by ordinary command-line programs. Keep this
; list explicit: caller filesystem scopes are added below and must not inherit
; an accidental read/write grant from the fixed profile.
(allow file-read* file-test-existence
  (subpath "/usr/lib")
  (subpath "/usr/share")
  (subpath "/Library/Apple")
  (subpath "/Library/Filesystems/NetFSPlugins")
  (subpath "/Library/Preferences/Logging")
  (subpath "/private/var/db/DarwinDirectory/local/recordStore.data")
  (subpath "/private/var/db/timezone")
  (subpath "/var/db")
  (subpath "/private/var/db"))
(allow file-read* file-test-existence
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/System/iOSSupport/System/Library/Frameworks")
  (subpath "/System/iOSSupport/System/Library/PrivateFrameworks")
  (subpath "/System/iOSSupport/System/Library/SubFrameworks")
  (subpath "/usr/lib"))
(allow file-read* (subpath "/opt/homebrew/lib"))
(allow file-read* (subpath "/usr/local/lib"))
(allow file-map-executable
  (subpath "/Library/Apple/System/Library/Frameworks")
  (subpath "/Library/Apple/System/Library/PrivateFrameworks")
  (subpath "/Library/Apple/usr/lib")
  (subpath "/System/Library/Extensions")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/SubFrameworks")
  (subpath "/System/iOSSupport/System/Library/Frameworks")
  (subpath "/System/iOSSupport/System/Library/PrivateFrameworks")
  (subpath "/System/iOSSupport/System/Library/SubFrameworks")
  (subpath "/usr/lib"))
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
(allow file-read-metadata file-test-existence
  (literal "/etc")
  (literal "/tmp")
  (literal "/var")
  (literal "/private/etc/localtime"))
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/zero"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))
(allow file-write-data
  (require-all
    (path "/dev/null")
    (vnode-type CHARACTER-DEVICE)))
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-read* (regex "^/dev/fd/(0|1|2)$"))
(allow file-write* (regex "^/dev/fd/(1|2)$"))
(allow file-read* file-write* (literal "/dev/tty"))
(allow file-read-metadata (literal "/dev"))
(allow file-read-metadata (regex "^/dev/.*$"))
(allow file-read-metadata
  (literal "/dev/stdin")
  (literal "/dev/stdout")
  (literal "/dev/stderr"))
(allow file-read-metadata (regex "^/dev/tty[^/]*$"))
(allow file-read-metadata (regex "^/dev/pty[^/]*$"))
(allow file-read* file-write*
  (require-all
    (regex "^/dev/ttys[0-9]+$")
    (extension "com.apple.sandbox.pty")))
(allow file-ioctl (regex "^/dev/ttys[0-9]+$"))
(allow pseudo-tty)

; Standard runtimes query hardware, process, and OS metadata through sysctl.
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.busfrequency_compat")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency_compat")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat")
  (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat")
  (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.model")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.nperflevels")
  (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.cpufrequency")
  (sysctl-name "hw.tbfrequency_compat")
  (sysctl-name "hw.vectorunit")
  (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "sysctl.proc_cputype")
  (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "net.routetable."))

; macOS classifies this read-only CPU query as a syscall write.
(allow sysctl-write (sysctl-name "kern.grade_cputype"))

; Standard library and runtime support used by command descendants.
(allow iokit-open
  (iokit-registry-entry-class "RootDomainUserClient"))
(allow system-mac-syscall (mac-policy-name "vnguard"))
(allow system-mac-syscall
  (require-all
    (mac-policy-name "Sandbox")
    (mac-syscall-number 67)))
(allow system-fsctl (fsctl-command FSIOC_CAS_BSDFLAGS))
(allow user-preference-read)
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data
  ipc-posix-shm-write-create
  ipc-posix-shm-write-unlink
  (ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$"))
(allow ipc-posix-shm-read* (ipc-posix-name-prefix "apple.cfprefs."))
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.cfprefsd.agent")
  (global-name "com.apple.PowerManagement.control")
  (local-name "com.apple.cfprefsd.agent"))

; System aliases, firmlinks, and special files needed during process startup.
(allow file-read* file-test-existence
  (subpath "/Library/Filesystems/NetFSPlugins")
  (subpath "/Library/Preferences/Logging")
  (subpath "/private/var/db/DarwinDirectory/local/recordStore.data")
  (subpath "/private/var/db/timezone")
  (literal "/dev/autofs_nowait")
  (literal "/private/etc/master.passwd")
  (literal "/private/etc/passwd")
  (literal "/private/etc/protocols")
  (literal "/private/etc/services")
  (literal "/System/Library/CoreServices")
  (literal "/System/Library/CoreServices/.SystemVersionPlatform.plist")
  (literal "/System/Library/CoreServices/SystemVersion.plist"))
(allow file-read-metadata file-test-existence
  (path-ancestors "/System/Volumes/Data/private"))
(allow file-read-metadata file-test-existence
  (literal "/System/Volumes")
  (literal "/System/Volumes/Data")
  (literal "/System/Volumes/Data/Users"))
(allow file-read* file-test-existence
  (literal "/System/Volumes/Data")
  (literal "/System/Volumes/Data/Users")
  (literal "/"))
(allow file-read* file-test-existence file-write-data file-ioctl
  (literal "/dev/dtracehelper"))
(allow mach-lookup
  (global-name "com.apple.analyticsd")
  (global-name "com.apple.analyticsd.messagetracer")
  (global-name "com.apple.appsleep")
  (global-name "com.apple.diagnosticd")
  (global-name "com.apple.dt.automationmode.reader")
  (global-name "com.apple.espd")
  (global-name "com.apple.logd")
  (global-name "com.apple.logd.events")
  (global-name "com.apple.runningboard")
  (global-name "com.apple.secinitd")
  (global-name "com.apple.system.DirectoryService.libinfo_v1")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.xpc.activity.unmanaged"))
(allow network-outbound (literal "/private/var/run/syslog"))
(allow ipc-posix-shm-read* (ipc-posix-name "apple.shm.notification_center"))
(allow file-read* (literal "/private/var/db/eligibilityd/eligibility.plist"))
(allow mach-lookup
  (global-name "com.apple.audio.audiohald")
  (global-name "com.apple.audio.AudioComponentRegistrar"))
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
        builder.add_filesystem(filesystem)?;
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

    fn add_filesystem(&mut self, plan: &MacosFilesystemPlan) -> Result<(), SeatbeltProfileError> {
        for (index, path) in plan.denied_paths().iter().enumerate() {
            self.add_definition(format!("DENIED_PATH_{index}"), path.clone())?;
        }
        for (index, path) in plan.write_denied_paths().iter().enumerate() {
            self.add_definition(format!("WRITE_DENIED_PATH_{index}"), path.clone())?;
        }
        if plan.unrestricted() {
            self.add_full_root("file-read*", plan.denied_paths(), &[])?;
            self.add_full_root(
                "file-write*",
                plan.denied_paths(),
                plan.write_denied_paths(),
            )?;
        } else {
            self.add_roots(
                "file-read*",
                "READ_ROOT",
                plan.read_roots(),
                plan.denied_paths(),
                plan.denied_globs(),
                &[],
            )?;
            self.add_roots(
                "file-write*",
                "WRITE_ROOT",
                plan.write_roots(),
                plan.denied_paths(),
                plan.denied_globs(),
                plan.write_denied_paths(),
            )?;
        }
        self.add_denied_glob_rules(plan.denied_globs())?;
        for (index, _path) in plan.denied_paths().iter().enumerate() {
            let name = format!("DENIED_PATH_{index}");
            self.policy
                .push_str(&format!("(deny file-read* (subpath (param \"{name}\")))\n"));
            self.policy.push_str(&format!(
                "(deny file-write* (subpath (param \"{name}\")))\n"
            ));
            self.policy.push_str(&format!(
                "(deny file-write-unlink (subpath (param \"{name}\")))\n"
            ));
        }
        for (index, _) in plan.write_denied_paths().iter().enumerate() {
            let name = format!("WRITE_DENIED_PATH_{index}");
            self.policy.push_str(&format!(
                "(deny file-write* (subpath (param \"{name}\")))\n"
            ));
            self.policy.push_str(&format!(
                "(deny file-write-unlink (subpath (param \"{name}\")))\n"
            ));
        }
        Ok(())
    }

    fn add_denied_glob_rules(&mut self, patterns: &[String]) -> Result<(), SeatbeltProfileError> {
        for pattern in patterns {
            if pattern.as_bytes().contains(&0) {
                return Err(SeatbeltProfileError::GlobContainsNul {
                    pattern: pattern.clone(),
                });
            }
            let regex = escape_regex_literal(&glob_to_seatbelt_regex(pattern));
            self.policy
                .push_str(&format!("(deny file-read* (regex #\"{regex}\"))\n"));
            self.policy
                .push_str(&format!("(deny file-write* (regex #\"{regex}\"))\n"));
            self.policy
                .push_str(&format!("(deny file-write-create (regex #\"{regex}\"))\n"));
            self.policy
                .push_str(&format!("(deny file-write-unlink (regex #\"{regex}\"))\n"));
        }
        Ok(())
    }

    fn add_roots(
        &mut self,
        action: &str,
        prefix: &str,
        roots: &[PathBuf],
        denied_paths: &[PathBuf],
        denied_globs: &[String],
        write_denied_paths: &[PathBuf],
    ) -> Result<(), SeatbeltProfileError> {
        if roots.is_empty() {
            return Ok(());
        }
        self.policy.push_str(&format!("\n(allow {action}\n"));
        for (index, path) in roots.iter().enumerate() {
            let name = format!("{prefix}_{index}");
            self.add_definition(name.clone(), path.clone())?;
            let mut requirements = vec![format!("(subpath (param \"{name}\"))")];
            for (excluded_index, excluded) in denied_paths.iter().enumerate() {
                if is_within(excluded, path) {
                    self.push_path_exclusion(&mut requirements, "DENIED_PATH", excluded_index);
                }
            }
            for pattern in denied_globs {
                let regex = glob_to_seatbelt_regex(pattern);
                requirements.push(format!(
                    r#"(require-not (regex #"{}"))"#,
                    escape_regex_literal(&regex)
                ));
            }
            if action == "file-write*" {
                for (excluded_index, excluded) in write_denied_paths.iter().enumerate() {
                    if is_within(excluded, path) {
                        self.push_path_exclusion(
                            &mut requirements,
                            "WRITE_DENIED_PATH",
                            excluded_index,
                        );
                    }
                }
            }
            self.policy
                .push_str(&format!("  (require-all {})\n", requirements.join(" ")));
        }
        self.policy.push_str(")\n");
        Ok(())
    }

    fn add_full_root(
        &mut self,
        action: &str,
        denied_paths: &[PathBuf],
        write_denied_paths: &[PathBuf],
    ) -> Result<(), SeatbeltProfileError> {
        let mut requirements = vec!["(subpath \"/\")".to_owned()];
        for (index, _) in denied_paths.iter().enumerate() {
            self.push_path_exclusion(&mut requirements, "DENIED_PATH", index);
        }
        if action == "file-write*" {
            for (index, _) in write_denied_paths.iter().enumerate() {
                self.push_path_exclusion(&mut requirements, "WRITE_DENIED_PATH", index);
            }
        }
        self.policy.push_str(&format!(
            "\n(allow {action} (require-all {}))\n",
            requirements.join(" ")
        ));
        Ok(())
    }

    fn push_path_exclusion(&self, requirements: &mut Vec<String>, prefix: &str, index: usize) {
        let name = format!("{prefix}_{index}");
        requirements.push(format!("(require-not (literal (param \"{name}\")))"));
        requirements.push(format!("(require-not (subpath (param \"{name}\")))"));
    }

    fn add_network(&mut self, network: &MacosNetworkPlan) -> Result<(), SeatbeltProfileError> {
        match network {
            MacosNetworkPlan::Disabled { unix } => {
                self.add_unix_socket_rules(unix, false)?;
            }
            MacosNetworkPlan::Direct { unix } => {
                self.policy
                    .push_str("\n(allow network-outbound)\n(allow network-inbound)\n");
                self.policy.push_str(SEATBELT_NETWORK_SERVICE_POLICY);
                self.add_unix_socket_rules(unix, true)?;
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
                self.add_unix_socket_rules(unix, true)?;
            }
        }
        Ok(())
    }

    fn add_unix_socket_rules(
        &mut self,
        plan: &MacosUnixSocketPlan,
        enabled: bool,
    ) -> Result<(), SeatbeltProfileError> {
        if !enabled || (!plan.allow_all() && plan.allowed().is_empty()) {
            return Ok(());
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
            self.add_definition(name.clone(), path.clone())?;
            self.policy.push_str(&format!(
                "(allow network-bind (local unix-socket (subpath (param \"{name}\"))))\n"
            ));
            self.policy.push_str(&format!(
                "(allow network-outbound (remote unix-socket (subpath (param \"{name}\"))))\n"
            ));
        }
        Ok(())
    }

    fn add_definition(&mut self, name: String, value: PathBuf) -> Result<(), SeatbeltProfileError> {
        if value.as_os_str().as_bytes().contains(&0) {
            return Err(SeatbeltProfileError::PathContainsNul { path: value });
        }
        if name.is_empty() || name.contains('\0') {
            return Err(SeatbeltProfileError::InvalidDefinitionName { name });
        }
        self.definitions.push(SeatbeltDefinition { name, value });
        Ok(())
    }

    fn finish(self) -> SeatbeltProfile {
        SeatbeltProfile {
            policy: self.policy,
            definitions: self.definitions,
        }
    }
}

pub(crate) fn glob_to_seatbelt_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let characters: Vec<char> = pattern.chars().collect();
    let mut index = 0;
    translate_glob_sequence(&characters, &mut index, None, &mut regex);
    if !pattern_has_glob_meta(pattern) {
        regex.push_str("(/.*)?");
    }
    regex.push('$');
    regex
}

fn pattern_has_glob_meta(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|character| matches!(character, '*' | '?' | '[' | '{' | '}'))
}

fn translate_glob_sequence(
    characters: &[char],
    index: &mut usize,
    terminator: Option<char>,
    regex: &mut String,
) {
    while *index < characters.len() {
        let character = characters[*index];
        if Some(character) == terminator || (terminator == Some('}') && character == ',') {
            return;
        }
        match character {
            '*' => translate_glob_stars(characters, index, regex),
            '?' => {
                *index += 1;
                regex.push_str("[^/]");
            }
            '[' => {
                translate_glob_class(characters, index, regex);
            }
            '{' => {
                translate_glob_alternation(characters, index, regex);
            }
            ']' | '}' => {
                *index += 1;
                push_regex_literal(regex, character);
            }
            _ => {
                *index += 1;
                push_regex_literal(regex, character);
            }
        }
    }
}

fn translate_glob_class(characters: &[char], index: &mut usize, regex: &mut String) {
    let start = *index;
    let mut class_index = start + 1;
    let negated = matches!(characters.get(class_index), Some('!') | Some('^'));
    if negated {
        class_index += 1;
    }

    let mut first = true;
    let mut in_range = false;
    let mut ranges = Vec::new();
    let Some(content_end) = (loop {
        let Some(&character) = characters.get(class_index) else {
            break None;
        };
        match character {
            ']' if first => {
                ranges.push((']', ']'));
                first = false;
                class_index += 1;
            }
            ']' => {
                break Some(class_index);
            }
            '-' if first => {
                ranges.push(('-', '-'));
                first = false;
                class_index += 1;
            }
            '-' if in_range => {
                if let Some(range) = ranges.last_mut() {
                    range.1 = '-';
                }
                in_range = false;
                first = false;
                class_index += 1;
            }
            '-' => {
                in_range = true;
                first = false;
                class_index += 1;
            }
            character if in_range => {
                if let Some(range) = ranges.last_mut() {
                    range.1 = character;
                }
                in_range = false;
                first = false;
                class_index += 1;
            }
            character => {
                ranges.push((character, character));
                first = false;
                class_index += 1;
            }
        }
    }) else {
        // Valid public PathPattern values cannot reach this branch. Keeping
        // malformed internal input literal prevents a partial class from
        // becoming a different, broader regular expression.
        push_regex_literal(regex, '[');
        *index = start + 1;
        return;
    };

    if in_range {
        ranges.push(('-', '-'));
    }

    regex.push('[');
    if negated {
        regex.push('^');
    }

    for (range_start, range_end) in ranges {
        push_regex_class_character(regex, range_start);
        if range_start != range_end {
            regex.push('-');
            push_regex_class_character(regex, range_end);
        }
    }
    regex.push(']');
    *index = content_end + 1;
}

fn translate_glob_stars(characters: &[char], index: &mut usize, regex: &mut String) {
    let start = *index;
    while characters.get(*index) == Some(&'*') {
        *index += 1;
    }
    let count = *index - start;
    let at_component_boundary = start == 0
        || matches!(
            characters.get(start.wrapping_sub(1)),
            Some('/') | Some('{') | Some(',')
        );

    // This is the globset recursive-prefix form. A longer run such as ***
    // remains a normal component wildcard, just as globset parses it.
    if count == 2 && at_component_boundary && characters.get(*index) == Some(&'/') {
        *index += 1;
        regex.push_str("(.*/)?");
    } else if count == 2
        && at_component_boundary
        && characters
            .get(*index)
            .is_none_or(|character| matches!(character, '}' | ','))
    {
        regex.push_str(".*");
    } else {
        regex.push_str("[^/]*");
    }
}

fn push_regex_class_character(regex: &mut String, character: char) {
    if matches!(character, '\\' | ']' | '[' | '^') {
        regex.push('\\');
    }
    regex.push(character);
}

fn translate_glob_alternation(characters: &[char], index: &mut usize, regex: &mut String) {
    let opening_index = *index;
    *index += 1;
    let mut branches = Vec::new();
    loop {
        let mut branch = String::new();
        translate_glob_sequence(characters, index, Some('}'), &mut branch);
        if *index >= characters.len() {
            // Valid public PathPattern values cannot reach this branch. Keep
            // malformed internal input literal and the generated expression
            // valid instead of leaving an unterminated regular-expression
            // group in the profile.
            push_regex_literal(regex, '{');
            *index = opening_index + 1;
            return;
        }
        match characters[*index] {
            ',' => {
                if !branch.is_empty() {
                    branches.push(branch);
                }
                *index += 1;
            }
            '}' => {
                if !branch.is_empty() {
                    branches.push(branch);
                }
                *index += 1;
                break;
            }
            _ => {
                // Defensive recovery for malformed internal input. Public
                // PathPattern construction rejects unbalanced alternations.
                push_regex_literal(regex, '{');
                *index = opening_index + 1;
                return;
            }
        }
    }

    if branches.len() == 1 {
        regex.push_str(&branches[0]);
    } else if !branches.is_empty() {
        regex.push('(');
        regex.push_str(&branches.join("|"));
        regex.push(')');
    }
}

fn push_regex_literal(regex: &mut String, character: char) {
    if matches!(
        character,
        '[' | ']' | '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '\\'
    ) {
        regex.push('\\');
    }
    regex.push(character);
}

fn escape_regex_literal(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => ['\\', '"'].into_iter().collect::<Vec<_>>(),
            character => [character].into_iter().collect::<Vec<_>>(),
        })
        .collect()
}
