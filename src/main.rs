pub mod cli;
pub mod engine;
pub mod hook;
pub mod invoke;
pub mod output;
pub mod report;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use std::fs;
use std::process;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            binary,
            markdown,
            json,
        } => {
            if !binary.exists() {
                eprintln!(
                    "  {} binary not found: {}",
                    "error:".bold().red(),
                    binary.display()
                );
                process::exit(1);
            }

            if markdown.is_none() && json.is_none() {
                eprintln!(
                    "  {} specify --markdown or --json (or both)",
                    "error:".bold().red()
                );
                process::exit(1);
            }

            let binary_path = match binary.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "  {} cannot resolve path {}: {e}",
                        "error:".bold().red(),
                        binary.display()
                    );
                    process::exit(1);
                }
            };

            let report = engine::analyze(&binary_path);

            if let Some(ref dest) = json {
                let json_str = report::json::render(&report);
                if dest == "-" {
                    println!("{json_str}");
                } else {
                    fs::write(dest, &json_str).unwrap_or_else(|e| {
                        eprintln!("  {} failed to write {dest}: {e}", "error:".bold().red());
                        process::exit(1);
                    });
                    eprintln!("  {} wrote {}", "[seg]".bold().cyan(), dest.bold());
                }
            }

            if let Some(ref dest) = markdown {
                let md = report::markdown::render(&report);
                if dest == "-" {
                    println!("{md}");
                } else {
                    fs::write(dest, &md).unwrap_or_else(|e| {
                        eprintln!("  {} failed to write {dest}: {e}", "error:".bold().red());
                        process::exit(1);
                    });
                    eprintln!("  {} wrote {}", "[seg]".bold().cyan(), dest.bold());
                }
            }
        }

        Commands::Invoke {
            library,
            function,
            args,
            ret,
            addr,
        } => {
            if !library.exists() {
                eprintln!(
                    "  {} file not found: {}",
                    "error:".bold().red(),
                    library.display()
                );
                process::exit(1);
            }

            let lib_path = match library.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "  {} cannot resolve path {}: {e}",
                        "error:".bold().red(),
                        library.display()
                    );
                    process::exit(1);
                }
            };

            invoke::run(&lib_path, function.as_deref(), &args, &ret, addr.as_deref());
        }

        Commands::Hook {
            binary,
            function,
            action,
            replace_lib,
            binary_args,
        } => {
            if !binary.exists() {
                eprintln!(
                    "  {} binary not found: {}",
                    "error:".bold().red(),
                    binary.display()
                );
                process::exit(1);
            }

            let binary_path = match binary.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "  {} cannot resolve path {}: {e}",
                        "error:".bold().red(),
                        binary.display()
                    );
                    process::exit(1);
                }
            };

            if action == "replace" {
                if let Some(ref lib) = replace_lib {
                    if !lib.exists() {
                        eprintln!(
                            "  {} replacement library not found: {}",
                            "error:".bold().red(),
                            lib.display()
                        );
                        process::exit(1);
                    }
                }
            }

            hook::run(
                &binary_path,
                &function,
                &action,
                replace_lib.as_deref(),
                &binary_args,
            );
        }
    }
}
