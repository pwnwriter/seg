use colored::Colorize;
use std::process::Command;

pub fn print_header(tag: &str, message: &str) {
    eprintln!(
        "\n  {} {}",
        format!("[{tag}]").bold().cyan(),
        message.bold()
    );
    eprintln!("  {}", "│".bright_black());
}

pub fn print_phase(name: &str, is_last: bool) {
    let connector = if is_last { "└──" } else { "├──" };
    eprintln!("  {} {}", connector.bright_black(), name.bold());
}

pub fn print_step(label: &str, is_last_step: bool, is_last_phase: bool) {
    let trunk = if is_last_phase { " " } else { "│" };
    let connector = if is_last_step {
        "└──"
    } else {
        "├──"
    };
    eprintln!(
        "  {}   {} {}",
        trunk.bright_black(),
        connector.bright_black(),
        label.bright_black(),
    );
}

pub fn print_done(tag: &str, elapsed: std::time::Duration) {
    eprintln!(
        "\n  {} {} {:.1}s\n",
        format!("[{tag}]").bold().cyan(),
        "done in".bold().green(),
        elapsed.as_secs_f64(),
    );
}

pub fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{program} failed: {stderr}"))
    }
}
