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

    /// Call exported functions from shared libraries or binary addresses
    #[command(visible_aliases = ["inv", "invo", "invok"])]
    Invoke {
        /// Path to the shared library or binary
        library: PathBuf,

        /// Function name to call (omit when using --addr)
        #[arg(required_unless_present = "addr")]
        function: Option<String>,

        /// Return type (i32, i64, u32, u64, f32, f64, string, pointer, void)
        #[arg(long, default_value = "void")]
        ret: String,

        /// Call by address instead of symbol name (e.g. 0x401234)
        #[arg(long)]
        addr: Option<String>,

        /// Arguments as type:value pairs (e.g. i32:42 f64:3.14 string:hello). Use -- before args.
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Hook functions in a binary via LD_PRELOAD / DYLD_INSERT_LIBRARIES
    #[command(visible_aliases = ["hk"])]
    Hook {
        /// Path to the target binary
        binary: PathBuf,

        /// Function name to hook
        function: String,

        /// Hook action: log calls or replace with another implementation
        #[arg(long, default_value = "log", value_parser = ["log", "replace"])]
        action: String,

        /// Shared library containing the replacement function (required for --action replace)
        #[arg(long, required_if_eq("action", "replace"))]
        replace_lib: Option<PathBuf>,

        /// Arguments to pass to the target binary (use -- before them)
        #[arg(last = true)]
        binary_args: Vec<String>,
    },
}
