// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::path::Component;

#[cfg(windows)]
use std::borrow::Cow;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum NativeComponentKey {
    Prefix(NativeOsKey),
    RootDir,
    CurDir,
    ParentDir,
    Normal(NativeOsKey),
}

#[cfg(not(windows))]
pub(crate) type NativeOsKey = OsString;

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum NativeOsKey {
    Folded(Vec<u16>),
    IllFormed(Vec<u16>),
}

pub(crate) fn component_key(component: Component<'_>) -> NativeComponentKey {
    match component {
        Component::Prefix(prefix) => NativeComponentKey::Prefix(native_os_key(prefix.as_os_str())),
        Component::RootDir => NativeComponentKey::RootDir,
        Component::CurDir => NativeComponentKey::CurDir,
        Component::ParentDir => NativeComponentKey::ParentDir,
        Component::Normal(value) => NativeComponentKey::Normal(native_os_key(value)),
    }
}

pub(crate) fn components_equal(left: Component<'_>, right: Component<'_>) -> bool {
    component_key(left) == component_key(right)
}

#[cfg(not(windows))]
fn native_os_key(value: &OsStr) -> NativeOsKey {
    value.to_os_string()
}

#[cfg(windows)]
pub(crate) fn normalize_windows_device_path(path: &Path) -> Cow<'_, Path> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < 7
        || !is_separator(units[0])
        || !is_separator(units[1])
        || (units[2] != b'?' as u16 && units[2] != b'.' as u16)
        || !is_separator(units[3])
    {
        return Cow::Borrowed(path);
    }

    let remainder = &units[4..];
    if remainder.len() >= 4
        && eq_ascii_case(remainder[0], b'U')
        && eq_ascii_case(remainder[1], b'N')
        && eq_ascii_case(remainder[2], b'C')
        && is_separator(remainder[3])
    {
        let mut normalized = vec![b'\\' as u16, b'\\' as u16];
        normalized.extend_from_slice(&remainder[4..]);
        return Cow::Owned(PathBuf::from(OsString::from_wide(&normalized)));
    }

    if remainder.len() >= 3
        && is_ascii_alpha(remainder[0])
        && remainder[1] == b':' as u16
        && is_separator(remainder[2])
    {
        return Cow::Owned(PathBuf::from(OsString::from_wide(remainder)));
    }

    Cow::Borrowed(path)
}

#[cfg(windows)]
fn is_separator(unit: u16) -> bool {
    matches!(unit, value if value == b'\\' as u16 || value == b'/' as u16)
}

#[cfg(windows)]
fn is_ascii_alpha(unit: u16) -> bool {
    unit <= u16::from(u8::MAX) && (unit as u8).is_ascii_alphabetic()
}

#[cfg(windows)]
fn eq_ascii_case(unit: u16, expected: u8) -> bool {
    unit <= u16::from(u8::MAX) && (unit as u8).eq_ignore_ascii_case(&expected)
}

#[cfg(windows)]
fn native_os_key(value: &OsStr) -> NativeOsKey {
    let units = value.encode_wide().collect::<Vec<_>>();
    match String::from_utf16(&units) {
        Ok(value) => NativeOsKey::Folded(value.to_lowercase().encode_utf16().collect()),
        Err(_) => NativeOsKey::IllFormed(units),
    }
}
