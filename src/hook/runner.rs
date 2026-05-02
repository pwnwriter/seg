use std::path::Path;
use std::process::Command;

pub fn run_hooked(
    binary: &Path,
    hook_lib: &Path,
    binary_args: &[String],
) -> Result<(String, String), String> {
    let preload_var = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };

    if cfg!(target_os = "macos") {
        eprintln!(
            "  {} macOS SIP may strip DYLD_INSERT_LIBRARIES for system binaries",
            colored::Colorize::yellow("note:")
        );
    }

    let output = Command::new(binary)
        .args(binary_args)
        .env(preload_var, hook_lib)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", binary.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((stdout, stderr))
}
