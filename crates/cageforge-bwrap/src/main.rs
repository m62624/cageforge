// SPDX-License-Identifier: Apache-2.0

//! Build-and-stage entry point for the upstream Bubblewrap implementation.

fn main() {
    if !cfg!(target_os = "linux") {
        eprintln!("cageforge-bwrap can only build Bubblewrap for Linux");
        std::process::exit(2);
    }

    let mut arguments = std::env::args_os().skip(1);
    let output = match (arguments.next().as_deref(), arguments.next()) {
        (Some(value), Some(path)) if value == "--output" && arguments.next().is_none() => {
            std::path::PathBuf::from(path)
        }
        _ => {
            eprintln!("usage: cageforge-bwrap --output PATH");
            std::process::exit(2);
        }
    };

    let built = std::path::Path::new(env!("CAGEFORGE_BUILT_BWRAP"));
    if let Some(parent) = output.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!("failed to create {}: {error}", parent.display());
        std::process::exit(1);
    }
    if let Err(error) = std::fs::copy(built, &output) {
        eprintln!("failed to stage {}: {error}", output.display());
        std::process::exit(1);
    }
    #[cfg(unix)]
    if let Err(error) = make_executable(&output) {
        eprintln!("failed to mark {} executable: {error}", output.display());
        std::process::exit(1);
    }
    let digest = match sha256_file(&output) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("failed to hash {}: {error}", output.display());
            std::process::exit(1);
        }
    };
    let digest_path = output.with_file_name("bwrap.sha256");
    if let Err(error) = std::fs::write(&digest_path, format!("{digest}\n")) {
        eprintln!("failed to write {}: {error}", digest_path.display());
        std::process::exit(1);
    }
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    std::fs::set_permissions(path, permissions)
}
