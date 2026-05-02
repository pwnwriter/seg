pub mod dlcall;
pub mod ptrace_call;
pub mod types;

use std::path::Path;
use std::process;

use colored::Colorize;

use crate::output::{print_done, print_header, print_phase, print_step};

pub fn run(
    library: &Path,
    function: Option<&str>,
    args: &[String],
    ret: &str,
    addr: Option<&str>,
) {
    let start = std::time::Instant::now();

    let ret_type = types::FfiType::parse(ret).unwrap_or_else(|e| {
        eprintln!("  {} {e}", "error:".bold().red());
        process::exit(1);
    });

    let parsed_args: Vec<(types::FfiType, types::FfiValue)> = args
        .iter()
        .map(|a| {
            types::FfiValue::parse_arg(a).unwrap_or_else(|e| {
                eprintln!("  {} {e}", "error:".bold().red());
                process::exit(1);
            })
        })
        .collect();

    if let Some(addr_str) = addr {
        // ptrace path
        let addr_val = parse_address(addr_str).unwrap_or_else(|e| {
            eprintln!("  {} {e}", "error:".bold().red());
            process::exit(1);
        });

        print_header("seg", &format!("invoking @ {addr_str}"));
        print_phase("ptrace invoke", true);
        print_step("forking target binary", false, true);
        print_step("setting up registers", false, true);
        print_step("calling function", false, true);
        print_step("collecting return value", true, true);

        let result =
            ptrace_call::invoke_ptrace(library, addr_val, &parsed_args, &ret_type)
                .unwrap_or_else(|e| {
                    eprintln!("  {} {e}", "error:".bold().red());
                    process::exit(1);
                });

        print_done("seg", start.elapsed());
        println!("{result}");
    } else {
        // dlopen path
        let func_name = function.unwrap_or_else(|| {
            eprintln!(
                "  {} function name is required (or use --addr for address-based invocation)",
                "error:".bold().red()
            );
            process::exit(1);
        });

        print_header("seg", &format!("invoking {func_name}"));
        print_phase("dynamic invoke", true);
        print_step("loading library", false, true);
        print_step(
            &format!("resolving symbol '{func_name}'"),
            false,
            true,
        );
        print_step("calling function", false, true);
        print_step("reading return value", true, true);

        let result =
            dlcall::invoke_dl(library, func_name, &parsed_args, &ret_type).unwrap_or_else(|e| {
                eprintln!("  {} {e}", "error:".bold().red());
                process::exit(1);
            });

        print_done("seg", start.elapsed());
        println!("{result}");
    }
}

fn parse_address(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid address '{s}': {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("invalid address '{s}': {e}"))
    }
}
