mod binary;
mod checksec;
mod disassembly;
mod elf;
mod hints;
mod libc;
mod libraries;
mod strategy;
mod strings;
mod symbols;

use std::path::Path;
use std::process::Command;

use colored::Colorize;

use crate::report::*;

fn print_phase(name: &str, is_last: bool) {
    let connector = if is_last { "└──" } else { "├──" };
    eprintln!("  {} {}", connector.bright_black(), name.bold());
}

fn print_step(label: &str, is_last_step: bool, is_last_phase: bool) {
    let trunk = if is_last_phase { " " } else { "│" };
    let connector = if is_last_step { "└──" } else { "├──" };
    eprintln!(
        "  {}   {} {}",
        trunk.bright_black(),
        connector.bright_black(),
        label.bright_black(),
    );
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String, String> {
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

pub fn analyze(binary_path: &Path) -> Report {
    let path_str = binary_path.to_string_lossy().to_string();
    let name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let start = std::time::Instant::now();
    let mut errors: Vec<String> = Vec::new();

    eprintln!("\n  {} analyzing {}", "[seg]".bold().cyan(), name.bold());
    eprintln!("  {}", "│".bright_black());

    // ── recon ──
    print_phase("recon", false);

    print_step("identifying file type", false, false);
    let file_output = run_cmd("file", &[&path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("reading file metadata", false, false);
    let stat_output = run_cmd("stat", &["-c", "%s %a %U %Y", &path_str])
        .or_else(|_| run_cmd("stat", &["-f", "%z %Lp %Su %m", &path_str]))
        .unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    print_step("computing sha256 hash", true, false);
    let sha256 = run_cmd("shasum", &["-a", "256", &path_str])
        .or_else(|_| run_cmd("sha256sum", &[&path_str]))
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    // ── binary analysis ──
    print_phase("binary analysis", false);

    print_step("parsing ELF headers", false, false);
    let readelf_h_output = run_cmd("readelf", &["-h", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("reading program segments", false, false);
    let readelf_l_output = run_cmd("readelf", &["-l", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("reading sections", false, false);
    let readelf_s_output = run_cmd("readelf", &["-S", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("reading dynamic entries", true, false);
    let readelf_d_output = run_cmd("readelf", &["-d", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    let readelf_output =
        format!("{readelf_h_output}\n{readelf_l_output}\n{readelf_s_output}\n{readelf_d_output}");

    // ── extraction ──
    print_phase("extraction", false);

    print_step("extracting strings", false, false);
    let strings_output = run_cmd("strings", &["-a", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("resolving libraries", false, false);
    let ldd_output = run_cmd("ldd", &[&path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("checking security mitigations", false, false);
    let checksec_output = run_cmd("checksec", &["--file", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("extracting symbols", true, false);
    let readelf_dynsym_output =
        run_cmd("readelf", &["--dyn-syms", &path_str]).unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    let objdump_plt_output =
        run_cmd("objdump", &["-d", "-j", ".plt", &path_str]).unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    let objdump_r_output = run_cmd("objdump", &["-R", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // ── analysis ──
    print_phase("analysis", true);

    print_step("disassembling binary", false, true);
    let objdump_d_output = run_cmd("objdump", &["-d", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    print_step("analyzing attack surface", false, true);
    let mut binary_info = binary::parse_file_output(&file_output, &path_str, &name, &sha256);
    let metadata = binary::parse_stat_output(&stat_output);
    let elf_headers = elf::parse_readelf_headers(&readelf_h_output, &mut binary_info);
    let segments = elf::parse_readelf_segments(&readelf_l_output);
    let sections = elf::parse_readelf_sections(&readelf_s_output);
    let strings_info = strings::parse_strings(&strings_output);
    let libraries = libraries::parse_ldd(&ldd_output);
    let dynamic = libraries::parse_dynamic_entries(&readelf_d_output);
    let protections = checksec::parse_checksec(&checksec_output);
    let syms = symbols::parse_symbols(&readelf_dynsym_output, &objdump_plt_output, &objdump_r_output);
    let disasm = disassembly::parse_disassembly(&objdump_d_output, &binary_info.entry_point);
    let dangerous_functions = disassembly::detect_dangerous_functions(&syms, &objdump_d_output);
    let exploitation_hints = hints::derive_hints(&protections, &dangerous_functions, &syms);
    let libc_info = libc::resolve_libc(&libraries, &syms);
    let strat = strategy::derive_strategy(&protections, &exploitation_hints, &dangerous_functions, &syms);

    print_step("building report", true, true);

    let elapsed = start.elapsed();
    eprintln!(
        "\n  {} {} {:.1}s\n",
        "[seg]".bold().cyan(),
        "done in".bold().green(),
        elapsed.as_secs_f64(),
    );

    let generated_at = chrono::Utc::now().to_rfc3339();

    Report {
        schema_version: "0.1.0".to_string(),
        tool: ToolInfo {
            name: "seg".to_string(),
            description: "Analyze. Understand. Exploit binaries".to_string(),
            command: format!("seg analyze {}", path_str),
            generated_at,
        },
        binary: binary_info,
        metadata,
        protections,
        elf: ElfInfo {
            headers: elf_headers,
            segments,
            sections,
        },
        libraries,
        dynamic,
        symbols: syms,
        strings: strings_info,
        disassembly: disasm,
        dangerous_functions,
        exploitation_hints,
        libc: libc_info,
        strategy: strat,
        ai_summary: AiSummary {
            one_line: String::new(),
            important_facts: vec![],
            recommended_path: String::new(),
        },
        raw_outputs: RawOutputs {
            file: file_output,
            stat: stat_output,
            ldd: ldd_output,
            checksec: checksec_output,
            readelf: readelf_output,
            objdump: objdump_plt_output.clone(),
            strings: strings_output,
        },
        errors,
    }
}
