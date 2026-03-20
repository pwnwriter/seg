pub mod cli;
pub mod engine;
pub mod report;

use clap::Parser;
use cli::{Cli, Commands};
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

            println!("analyzing: {}", binary_path.display());

            if let Some(ref dest) = markdown {
                if dest == "-" {
                    println!("[markdown -> stdout]");
                } else {
                    println!("[markdown -> {}]", dest);
                }
            }

            if let Some(ref dest) = json {
                if dest == "-" {
                    println!("[json -> stdout]");
                } else {
                    println!("[json -> {}]", dest);
                }
            }

            // TODO: run engine, generate report
            println!("(not implemented yet)");
        }
    }
}
