pub mod codegen;
pub mod compile;
pub mod runner;

use std::path::Path;
use std::process;

use colored::Colorize;

use crate::output::{print_done, print_header, print_phase, print_step};

pub fn run(
    binary: &Path,
    function: &str,
    action: &str,
    replace_lib: Option<&Path>,
    binary_args: &[String],
) {
    let start = std::time::Instant::now();

    print_header("seg", &format!("hooking {function}"));

    // phase 1: codegen
    print_phase("codegen", false);
    print_step("generating hook source", true, false);

    let c_source = match action {
        "log" => codegen::generate_log_hook(function),
        "replace" => {
            let lib = replace_lib.unwrap_or_else(|| {
                eprintln!(
                    "  {} --replace-lib is required for --action replace",
                    "error:".bold().red()
                );
                process::exit(1);
            });
            let lib_abs = lib.canonicalize().unwrap_or_else(|e| {
                eprintln!(
                    "  {} cannot resolve {}: {e}",
                    "error:".bold().red(),
                    lib.display()
                );
                process::exit(1);
            });
            codegen::generate_replace_hook(function, &lib_abs.to_string_lossy())
        }
        _ => unreachable!(),
    };

    // show the generated source
    eprintln!();
    for line in c_source.lines() {
        eprintln!("  {}", line.bright_black());
    }
    eprintln!();

    // phase 2: compile
    print_phase("compile", false);
    print_step("compiling with cc", true, false);

    let hook_lib = compile::compile_hook(&c_source).unwrap_or_else(|e| {
        eprintln!("  {} {e}", "error:".bold().red());
        process::exit(1);
    });

    eprintln!(
        "  {}   {} {}",
        "│".bright_black(),
        "→".bright_black(),
        hook_lib.display().to_string().bright_black(),
    );

    // phase 3: execute
    print_phase("execute", true);
    print_step(
        &format!("running {} with preload", binary.display()),
        true,
        true,
    );

    let (stdout, stderr) = runner::run_hooked(binary, &hook_lib, binary_args).unwrap_or_else(|e| {
        eprintln!("  {} {e}", "error:".bold().red());
        process::exit(1);
    });

    print_done("seg", start.elapsed());

    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    if !stdout.is_empty() {
        print!("{stdout}");
    }
}
