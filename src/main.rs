pub mod cli;
pub mod engine;
pub mod report;

use clap::Parser;
use cli::{Cli, Commands};
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
                eprintln!("error: binary not found: {}", binary.display());
                process::exit(1);
            }

            if markdown.is_none() && json.is_none() {
                eprintln!("error: specify --markdown or --json (or both)");
                process::exit(1);
            }

            let binary_path = match binary.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: cannot resolve path {}: {e}", binary.display());
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
                        eprintln!("error: failed to write {dest}: {e}");
                        process::exit(1);
                    });
                    eprintln!("wrote {dest}");
                }
            }

            if let Some(ref dest) = markdown {
                let md = report::markdown::render(&report);
                if dest == "-" {
                    println!("{md}");
                } else {
                    fs::write(dest, &md).unwrap_or_else(|e| {
                        eprintln!("error: failed to write {dest}: {e}");
                        process::exit(1);
                    });
                    eprintln!("wrote {dest}");
                }
            }
        }
    }
}
