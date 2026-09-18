// SPDX-License-Identifier: Apache-2.0

//! Regenerates the committed Python extension stub.

use std::path::Path;

fn main() -> pyo3_stub_gen::Result<()> {
    _cageforge::stub_info()?.generate()?;
    let generated = Path::new("python/cageforge/_cageforge").join("__init__.pyi");
    let target = Path::new("python/cageforge/_cageforge.pyi");
    if generated.is_file() {
        std::fs::rename(&generated, target)?;
        std::fs::remove_dir("python/cageforge/_cageforge")?;
    }
    let stub = std::fs::read_to_string(target)?;
    let stub = stub
        .replace("builtins.CageforgeError", "CageforgeError")
        .replace(
            "builtins.CageforgePermissionError",
            "CageforgePermissionError",
        )
        .replace("builtins.CageforgeStoreError", "CageforgeStoreError")
        .replace("os.PathLike", "os.PathLike[str]");
    let stub = format!("{}\n", stub.trim_end());
    std::fs::write(target, stub)?;
    println!("wrote {}", target.display());
    Ok(())
}
