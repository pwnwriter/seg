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

    let binary_info = parse_file_output(&file_output, &path_str, &name, &sha256);
    let metadata = parse_stat_output(&stat_output);

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
        protections: Protections {
            pie: false,
            nx: false,
            canary: false,
            relro: String::new(),
            fortify: false,
        },
        elf: ElfInfo {
            headers: ElfHeaders {
                elf_type: String::new(),
                machine: String::new(),
                abi: String::new(),
            },
            segments: vec![],
            sections: vec![],
        },
        libraries: Libraries {
            source: "ldd".to_string(),
            items: vec![],
        },
        dynamic: DynamicInfo {
            needed: vec![],
            entries: vec![],
        },
        symbols: Symbols {
            imports: vec![],
            exports: vec![],
        },
        strings: StringsInfo {
            shell: vec![],
            format_strings: vec![],
            paths: vec![],
            urls: vec![],
            suspicious: vec![],
        },
        disassembly: Disassembly {
            entry: String::new(),
            main: String::new(),
            suspicious_functions: vec![],
        },
        dangerous_functions: vec![],
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
            ldd: String::new(),
            checksec: String::new(),
            readelf: String::new(),
            objdump: String::new(),
            strings: String::new(),
        },
        errors,
    }
}

fn parse_file_output(output: &str, path: &str, name: &str, sha256: &str) -> BinaryInfo {
    let output = output.trim();

    let file_type = output
        .split(": ")
        .nth(1)
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let arch = if output.contains("x86-64") || output.contains("x86_64") {
        "x86_64"
    } else if output.contains("aarch64") || output.contains("ARM aarch64") {
        "aarch64"
    } else if output.contains("ARM") {
        "arm"
    } else if output.contains("80386") || output.contains("Intel 80386") {
        "i386"
    } else if output.contains("MIPS") {
        "mips"
    } else if output.contains("PowerPC") {
        "ppc"
    } else {
        "unknown"
    }
    .to_string();

    let bits = if output.contains("64-bit") {
        64
    } else if output.contains("32-bit") {
        32
    } else {
        0
    };

    let endianness = if output.contains("LSB") {
        "little"
    } else if output.contains("MSB") {
        "big"
    } else {
        "unknown"
    }
    .to_string();

    let stripped = output.contains("stripped") && !output.contains("not stripped");
    let is_static = output.contains("statically linked");

    let interpreter = if output.contains("interpreter") {
        output
            .split("interpreter ")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .unwrap_or("")
            .trim()
            .to_string()
    } else {
        String::new()
    };

    BinaryInfo {
        path: path.to_string(),
        name: name.to_string(),
        file_type,
        architecture: arch,
        bits,
        endianness,
        interpreter,
        stripped,
        is_static,
        entry_point: String::new(), // filled by readelf later
        sha256: sha256.to_string(),
    }
}

fn parse_stat_output(output: &str) -> FileMetadata {
    let parts: Vec<&str> = output.trim().split_whitespace().collect();
    if parts.len() >= 4 {
        let size_bytes = parts[0].parse::<u64>().unwrap_or(0);
        let permissions = parts[1].to_string();
        let owner = parts[2].to_string();
        let modified_time = parts[3].to_string();

        FileMetadata {
            size_bytes,
            permissions,
            owner,
            modified_time,
        }
    } else {
        FileMetadata {
            size_bytes: 0,
            permissions: String::new(),
            owner: String::new(),
            modified_time: String::new(),
        }
    }
}
