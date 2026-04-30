pub mod ascii;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "seg", about = ascii::splash(), arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a binary and generate a report
    #[command(visible_aliases = ["ana", "anal", "analy", "analyz"])]
    Analyze {
        /// Path to the binary to analyze
        binary: PathBuf,

        /// Output as Markdown (optionally to a file)
        #[arg(long, num_args = 0..=1, default_missing_value = "-")]
        markdown: Option<String>,

        /// Output as JSON (optionally to a file)
        #[arg(long, num_args = 0..=1, default_missing_value = "-")]
        json: Option<String>,
    },
}
