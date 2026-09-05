// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "build-from-source")]
use std::env;
#[cfg(feature = "build-from-source")]
use std::path::{Path, PathBuf};

#[cfg(feature = "build-from-source")]
const SOURCES: &[&str] = &["bubblewrap.c", "bind-mount.c", "network.c", "utils.c"];
#[cfg(feature = "build-from-source")]
const HEADERS: &[&str] = &["bind-mount.h", "network.h", "utils.h"];
#[cfg(feature = "build-from-source")]
const UPSTREAM_VERSION: &str = "0.11.2";
#[cfg(feature = "build-from-source")]
const UPSTREAM_COMMIT: &str = "1b80120ef26a28e065e67f89bfef873f13bdd317";

fn main() {
    #[cfg(feature = "build-from-source")]
    println!("cargo:rerun-if-env-changed=CAGEFORGE_BWRAP_SOURCE_DIR");
    #[cfg(feature = "build-from-source")]
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS");
    #[cfg(feature = "build-from-source")]
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    #[cfg(feature = "build-from-source")]
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR");

    #[cfg(feature = "build-from-source")]
    {
        let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
        let source_dir = source_dir(&manifest_dir);
        for file in SOURCES.iter().chain(HEADERS) {
            println!("cargo:rerun-if-changed={}", source_dir.join(file).display());
        }
    }

    #[cfg(feature = "embedded")]
    {
        for path in [
            "assets/linux-x86_64/bwrap",
            "assets/linux-x86_64/bwrap.sha256",
            "assets/linux-aarch64/bwrap",
            "assets/linux-aarch64/bwrap.sha256",
        ] {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    #[cfg(feature = "build-from-source")]
    {
        let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
        let source_dir = source_dir(&manifest_dir);
        if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
            println!("cargo:rustc-env=CAGEFORGE_BUILT_BWRAP=unavailable");
            return;
        }

        if let Err(error) = build_bwrap(&source_dir) {
            eprintln!(
                "error: failed to build upstream Bubblewrap {UPSTREAM_VERSION} ({UPSTREAM_COMMIT}): {error}"
            );
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "build-from-source")]
fn source_dir(manifest_dir: &Path) -> PathBuf {
    env::var_os("CAGEFORGE_BWRAP_SOURCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("vendor/bubblewrap"))
}

#[cfg(feature = "build-from-source")]
fn build_bwrap(source_dir: &Path) -> Result<(), String> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    for file in SOURCES.iter().chain(HEADERS) {
        if !source_dir.join(file).is_file() {
            return Err(format!(
                "missing Bubblewrap source file {}",
                source_dir.join(file).display()
            ));
        }
    }

    let config_h = out_dir.join("config.h");
    std::fs::write(
        &config_h,
        "#pragma once\n#define PACKAGE_STRING \"bubblewrap 0.11.2\"\n",
    )
    .map_err(|error| format!("failed to write {}: {error}", config_h.display()))?;

    let libcap = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("libcap")
        .map_err(|error| format!("libcap was not found through pkg-config: {error}"))?;

    let compiler = cc::Build::new()
        .try_get_compiler()
        .map_err(|error| format!("target C compiler is unavailable: {error}"))?;
    let binary = out_dir.join("bwrap");
    let mut command = compiler.to_command();
    command
        .arg("-D_GNU_SOURCE")
        .arg(format!("-I{}", out_dir.display()))
        .arg(format!("-I{}", source_dir.display()));
    for include_path in libcap.include_paths {
        command.arg(format!("-idirafter{}", include_path.display()));
    }
    for source in SOURCES {
        command.arg(source_dir.join(source));
    }
    for link_path in libcap.link_paths {
        command.arg(format!("-L{}", link_path.display()));
    }
    for library in libcap.libs {
        command.arg(format!("-l{library}"));
    }
    let output = command.arg("-o").arg(&binary).output().map_err(|error| {
        format!(
            "failed to invoke target C compiler {}: {error}",
            compiler.path().display()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "Bubblewrap compiler failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    println!("cargo:rustc-env=CAGEFORGE_BUILT_BWRAP={}", binary.display());
    Ok(())
}
