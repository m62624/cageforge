use cageforge_path::{contains_parent_traversal, is_within, paths_equal};
use std::path::Path;

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
