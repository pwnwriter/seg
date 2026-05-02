use std::path::PathBuf;

use crate::output::run_cmd;

pub fn compile_hook(c_source: &str) -> Result<PathBuf, String> {
    let tmp_dir = std::env::temp_dir().join("seg_hooks");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| format!("failed to create temp dir: {e}"))?;

    let src_path = tmp_dir.join("hook.c");
    let so_path = tmp_dir.join("hook.so");

    std::fs::write(&src_path, c_source)
        .map_err(|e| format!("failed to write hook source: {e}"))?;

    let src = src_path.to_string_lossy().to_string();
    let out = so_path.to_string_lossy().to_string();

    let mut args = vec!["-shared", "-fPIC", "-o", &out, &src];

    // -ldl needed on linux, not on macos (dlsym lives in libSystem)
    if cfg!(target_os = "linux") {
        args.push("-ldl");
    }

    run_cmd("cc", &args)?;

    Ok(so_path)
}
