use cageforge_config::Config;
use cageforge_policy::{
    FilesystemDecision, FilesystemTarget, MissingPathBehavior, PathPattern, PathResolutionContext,
    PathSelector,
};
use proptest::prelude::*;
use std::num::NonZeroUsize;
use std::path::PathBuf;

fn target_kind() -> impl Strategy<Value = u8> {
    0u8..=8
}

fn path_segment() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_-]{0,7}").expect("path segment regex")
}

fn relative_path() -> impl Strategy<Value = String> {
    prop::collection::vec(path_segment(), 1..=3).prop_map(|segments| segments.join("/"))
}

fn absolute_suffix() -> impl Strategy<Value = String> {
    prop::collection::vec(path_segment(), 1..=3).prop_map(|segments| segments.join("/"))
}

fn absolute_text(suffix: &str) -> String {
    #[cfg(windows)]
    {
        format!("C:/cageforge/{suffix}")
    }
    #[cfg(not(windows))]
    {
        format!("/cageforge/{suffix}")
    }
}

fn target_fragment(kind: u8, relative: &str, absolute: &str, missing_skip: bool) -> String {
    let missing = if missing_skip {
        "missing_path = \"skip\", "
    } else {
        "missing_path = \"error\", "
    };
    match kind {
        0 => format!(
            "target = \"absolute\", path = \"{}\", {missing}access = \"write\"",
            absolute_text(absolute)
        ),
        1 => format!("target = \"workspace\", path = \"{relative}\", {missing}access = \"write\""),
        2 => format!("target = \"workspace-root\", {missing}access = \"write\""),
        3 => format!("target = \"root\", {missing}access = \"write\""),
        4 => format!("target = \"minimal\", {missing}access = \"write\""),
        5 => format!("target = \"tmpdir\", {missing}access = \"write\""),
        6 => format!("target = \"slash-tmp\", {missing}access = \"write\""),
        7 => format!(
            "target = \"absolute-glob\", pattern = \"{}/**/*.secret\", access = \"deny\"",
            absolute_text(absolute)
        ),
        8 => format!(
            "target = \"workspace-glob\", pattern = \"{relative}/**/*.secret\", access = \"deny\""
        ),
        _ => unreachable!("strategy only produces known filesystem targets"),
    }
}

fn render_target_config(kind: u8, relative: &str, absolute: &str, missing_skip: bool) -> String {
    let rule = target_fragment(kind, relative, absolute, missing_skip);
    format!(
        r#"
default_profile = "targets"

[profiles.targets.filesystem]
mode = "restricted"
glob_scan_max_depth = 3
rules = [{{ {rule} }}]
"#
    )
}

fn expected_target(kind: u8, relative: &str, absolute: &str) -> FilesystemTarget {
    match kind {
        0 => FilesystemTarget::Scope(
            PathSelector::absolute(PathBuf::from(absolute_text(absolute))).unwrap(),
        ),
        1 => FilesystemTarget::Scope(PathSelector::workspace(relative).unwrap()),
        2 => FilesystemTarget::Scope(PathSelector::workspace_root()),
        3 => FilesystemTarget::Scope(PathSelector::root()),
        4 => FilesystemTarget::Scope(PathSelector::minimal()),
        5 => FilesystemTarget::Scope(PathSelector::tmpdir()),
        6 => FilesystemTarget::Scope(PathSelector::slash_tmp()),
        7 => FilesystemTarget::Glob(
            PathPattern::absolute(format!("{}/**/*.secret", absolute_text(absolute))).unwrap(),
        ),
        8 => FilesystemTarget::Glob(
            PathPattern::workspace(format!("{relative}/**/*.secret")).unwrap(),
        ),
        _ => unreachable!("strategy only produces known filesystem targets"),
    }
}

fn context() -> PathResolutionContext {
    PathResolutionContext::new()
        .with_root(PathBuf::from(absolute_text("root")))
        .unwrap()
        .with_workspace_root(PathBuf::from(absolute_text("workspace")))
        .unwrap()
        .with_minimal_path(PathBuf::from(absolute_text("minimal")))
        .unwrap()
        .with_tmpdir(PathBuf::from(absolute_text("tmpdir")))
        .unwrap()
        .with_slash_tmp(PathBuf::from(absolute_text("slash-tmp")))
        .unwrap()
}

fn probe_path(kind: u8, relative: &str, absolute: &str) -> PathBuf {
    let context_workspace = PathBuf::from(absolute_text("workspace"));
    match kind {
        0 => PathBuf::from(absolute_text(absolute)).join("file.txt"),
        1 => context_workspace.join(relative).join("file.txt"),
        2 => context_workspace.join("file.txt"),
        3 => PathBuf::from(absolute_text("root")).join("file.txt"),
        4 => PathBuf::from(absolute_text("minimal")).join("file.txt"),
        5 => PathBuf::from(absolute_text("tmpdir")).join("file.txt"),
        6 => PathBuf::from(absolute_text("slash-tmp")).join("file.txt"),
        7 => PathBuf::from(absolute_text(absolute)).join("nested/file.secret"),
        8 => context_workspace.join(relative).join("nested/file.secret"),
        _ => unreachable!("strategy only produces known filesystem targets"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn every_filesystem_target_roundtrips_and_resolves(
        kind in target_kind(),
        relative in relative_path(),
        absolute in absolute_suffix(),
        missing_skip in any::<bool>(),
    ) {
        let source = render_target_config(kind, &relative, &absolute, missing_skip);
        let resolved = Config::from_toml(&source)
            .expect("generated target config should parse")
            .resolve_default()
            .expect("generated target config should resolve");
        let filesystem = resolved.policy().filesystem();
        let rule = &filesystem.entries()[0];
        let expected_target = expected_target(kind, &relative, &absolute);

        prop_assert_eq!(rule.target(), &expected_target);
        prop_assert_eq!(filesystem.glob_scan_max_depth(), NonZeroUsize::new(3));
        prop_assert_eq!(
            rule.missing_path_behavior(),
            if kind < 7 && missing_skip {
                MissingPathBehavior::Skip
            } else {
                MissingPathBehavior::Error
            }
        );

        let decision = filesystem
            .access_for_path(&probe_path(kind, &relative, &absolute), &context())
            .expect("generated probe path should be absolute");
        prop_assert_eq!(
            decision,
            if kind < 7 {
                FilesystemDecision::Write
            } else {
                FilesystemDecision::Deny
            }
        );
    }
}
