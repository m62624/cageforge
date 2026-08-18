use cageforge_path::{contains_parent_traversal, is_within, paths_equal};
use proptest::prelude::*;
use std::path::Path;
use std::path::PathBuf;

#[test]
fn containment_is_component_aware() {
    assert!(is_within(
        Path::new("/workspace/src"),
        Path::new("/workspace")
    ));
    assert!(is_within(Path::new("/workspace"), Path::new("/workspace")));
    assert!(!is_within(
        Path::new("/workspace-other/src"),
        Path::new("/workspace")
    ));
}

#[test]
fn complete_paths_compare_components() {
    assert!(paths_equal(
        Path::new("/workspace/./src"),
        Path::new("/workspace/src")
    ));
    assert!(!paths_equal(
        Path::new("/workspace/src"),
        Path::new("/workspace/src2")
    ));
}

#[test]
fn parent_traversal_is_detected_without_filesystem_access() {
    assert!(contains_parent_traversal(Path::new("workspace/../outside")));
    assert!(!contains_parent_traversal(Path::new("workspace/src")));
}

fn absolute_root() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\workspace")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/workspace")
    }
}

fn append_segments(mut path: PathBuf, segments: &[String]) -> PathBuf {
    for segment in segments {
        path.push(segment);
    }
    path
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn generated_descendants_use_component_aware_native_containment(
        root_segments in prop::collection::vec(prop::string::string_regex("[a-z]{1,6}").expect("segment regex"), 0..=4),
        child_segments in prop::collection::vec(prop::string::string_regex("[a-z]{1,6}").expect("segment regex"), 0..=4),
    ) {
        let root = append_segments(absolute_root(), &root_segments);
        let descendant = append_segments(root.clone(), &child_segments);
        let dotted = append_segments(root.join("."), &child_segments);

        prop_assert!(is_within(&descendant, &root));
        prop_assert!(paths_equal(&descendant, &dotted));
        prop_assert!(!is_within(&descendant, &PathBuf::from("/workspace-other")));
        prop_assert!(!contains_parent_traversal(&descendant));
    }

    #[test]
    fn generated_parent_components_are_always_rejected(
        segments in prop::collection::vec(prop::string::string_regex("[a-z]{1,6}").expect("segment regex"), 0..=4),
    ) {
        let escaped = append_segments(absolute_root(), &segments).join("..").join("outside");

        prop_assert!(contains_parent_traversal(&escaped));
    }
}

#[cfg(windows)]
#[test]
fn windows_path_comparison_is_case_insensitive() {
    assert!(is_within(
        Path::new(r"C:\Workspace\src"),
        Path::new(r"c:\workspace")
    ));
    assert!(paths_equal(
        Path::new(r"C:\Workspace"),
        Path::new(r"c:\workspace")
    ));
}

#[cfg(not(windows))]
#[test]
fn posix_path_comparison_is_case_sensitive() {
    assert!(!is_within(
        Path::new("/Workspace/src"),
        Path::new("/workspace")
    ));
    assert!(!paths_equal(
        Path::new("/Workspace"),
        Path::new("/workspace")
    ));
}
