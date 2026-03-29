mod binary;
mod checksec;
mod disassembly;
mod elf;
mod libraries;
mod strings;
mod symbols;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::report::*;

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

    let mut errors: Vec<String> = Vec::new();

    // Run file
    let file_output = run_cmd("file", &[&path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run stat
    let stat_output = run_cmd("stat", &["-c", "%s %a %U %Y", &path_str])
        .or_else(|_| run_cmd("stat", &["-f", "%z %Lp %Su %m", &path_str]))
        .unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    // Compute sha256
    let sha256 = run_cmd("shasum", &["-a", "256", &path_str])
        .or_else(|_| run_cmd("sha256sum", &[&path_str]))
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    // Run readelf -h (headers)
    let readelf_h_output = run_cmd("readelf", &["-h", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run readelf -l (segments/program headers)
    let readelf_l_output = run_cmd("readelf", &["-l", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run readelf -S (sections)
    let readelf_s_output = run_cmd("readelf", &["-S", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run readelf -d (dynamic entries)
    let readelf_d_output = run_cmd("readelf", &["-d", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    let readelf_output =
        format!("{readelf_h_output}\n{readelf_l_output}\n{readelf_s_output}\n{readelf_d_output}");

    // Run strings
    let strings_output = run_cmd("strings", &["-a", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run ldd
    let ldd_output = run_cmd("ldd", &[&path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run checksec
    let checksec_output = run_cmd("checksec", &["--file", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run readelf --dyn-syms (dynamic symbols)
    let readelf_dynsym_output =
        run_cmd("readelf", &["--dyn-syms", &path_str]).unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    // Run objdump -d for PLT (just the .plt section)
    let objdump_plt_output =
        run_cmd("objdump", &["-d", "-j", ".plt", &path_str]).unwrap_or_else(|e| {
            errors.push(e);
            String::new()
        });

    // Run objdump -R for GOT relocations
    let objdump_r_output = run_cmd("objdump", &["-R", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Run objdump -d for full disassembly
    let objdump_d_output = run_cmd("objdump", &["-d", &path_str]).unwrap_or_else(|e| {
        errors.push(e);
        String::new()
    });

    // Parse all outputs
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
        exploitation_hints: ExploitationHints {
            buffer_overflow_likely: false,
            format_string_likely: false,
            ret2libc_possible: false,
            got_overwrite_possible: false,
            shellcode_possible: false,
            rop_likely: false,
            reasoning: vec![],
        },
        libc: LibcInfo {
            local: LocalLibc {
                source: String::new(),
                path: String::new(),
                runtime_base: String::new(),
            },
            libc_rip: LibcRip {
                enabled: false,
                endpoint: "https://libc.rip/api/find".to_string(),
                query: serde_json::Value::Null,
                matches: vec![],
                useful_symbols: HashMap::new(),
            },
        },
        strategy: Strategy {
            most_likely: String::new(),
            reason: String::new(),
            steps: vec![],
            leak_targets: vec![],
        },
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
