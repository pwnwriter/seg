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

    let mut binary_info = parse_file_output(&file_output, &path_str, &name, &sha256);
    let metadata = parse_stat_output(&stat_output);
    let elf_headers = parse_readelf_headers(&readelf_h_output, &mut binary_info);
    let segments = parse_readelf_segments(&readelf_l_output);
    let sections = parse_readelf_sections(&readelf_s_output);
    let strings_info = parse_strings(&strings_output);
    let libraries = parse_ldd(&ldd_output);
    let dynamic = parse_dynamic_entries(&readelf_d_output);

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
            headers: elf_headers,
            segments,
            sections,
        },
        libraries,
        dynamic,
        symbols: Symbols {
            imports: vec![],
            exports: vec![],
        },
        strings: strings_info,
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
            ldd: ldd_output,
            checksec: String::new(),
            readelf: readelf_output,
            objdump: String::new(),
            strings: strings_output,
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

fn readelf_field(output: &str, key: &str) -> String {
    output
        .lines()
        .find(|l| l.contains(key))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

fn parse_readelf_headers(output: &str, binary: &mut BinaryInfo) -> ElfHeaders {
    let entry = readelf_field(output, "Entry point address:");
    if !entry.is_empty() {
        binary.entry_point = entry;
    }

    ElfHeaders {
        elf_type: readelf_field(output, "Type:"),
        machine: readelf_field(output, "Machine:"),
        abi: readelf_field(output, "OS/ABI:"),
    }
}

fn parse_readelf_segments(output: &str) -> Vec<Segment> {
    // readelf -l output looks like:
    //   Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
    //   LOAD           0x000000 0x0000000000400000 0x0000000000400000 0x000abc 0x000abc R E 0x200000
    let mut segments = Vec::new();
    let mut in_table = false;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Type") && trimmed.contains("Offset") {
            in_table = true;
            continue;
        }

        if !in_table {
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("Section to Segment") {
            break;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 6 {
            // Check if first field looks like a segment type
            let seg_type = parts[0];
            if !seg_type
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
            {
                continue;
            }

            let offset = parts.get(1).unwrap_or(&"").to_string();
            let vaddr = parts.get(2).unwrap_or(&"").to_string();
            let filesz = parts.get(4).unwrap_or(&"").to_string();

            // Flags are typically near the end — look for R/W/E pattern
            let perms = parts
                .iter()
                .find(|p| {
                    p.len() <= 4
                        && p.chars().all(|c| matches!(c, 'R' | 'W' | 'E' | ' '))
                        && !p.is_empty()
                })
                .unwrap_or(&"")
                .to_string();

            segments.push(Segment {
                seg_type: seg_type.to_string(),
                offset,
                virtual_address: vaddr,
                size: filesz,
                permissions: perms,
            });
        }
    }

    segments
}

fn parse_readelf_sections(output: &str) -> Vec<Section> {
    // readelf -S output looks like:
    //   [Nr] Name              Type             Address           Offset
    //        Size              EntSize          Flags  Link  Info  Align
    //   [ 1] .text             PROGBITS         0000000000401000  00001000
    //        0000000000000250  0000000000000000  AX       0     0     16
    let mut sections = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // Match lines like "  [ 1] .text  PROGBITS ..."
        if line.starts_with('[') && line.contains(']') {
            let after_bracket = line.split(']').nth(1).unwrap_or("").trim();
            let parts: Vec<&str> = after_bracket.split_whitespace().collect();

            if parts.len() >= 4 {
                let name = parts[0].to_string();
                // Skip NULL section
                if name == "" || parts[1] == "NULL" {
                    i += 1;
                    continue;
                }

                let address = format!("0x{}", parts.get(2).unwrap_or(&""));
                let offset = format!("0x{}", parts.get(3).unwrap_or(&""));

                // Next line has size and flags
                let mut size = String::new();
                let mut flags = String::new();
                if i + 1 < lines.len() {
                    let next_parts: Vec<&str> = lines[i + 1].trim().split_whitespace().collect();
                    if !next_parts.is_empty() {
                        size = format!("0x{}", next_parts[0]);
                    }
                    if next_parts.len() >= 3 {
                        flags = next_parts[2].to_string();
                    }
                    i += 1;
                }

                sections.push(Section {
                    name,
                    address,
                    offset,
                    size,
                    flags,
                });
            }
        }

        i += 1;
    }

    sections
}

fn parse_strings(output: &str) -> StringsInfo {
    let mut shell = Vec::new();
    let mut format_strings = Vec::new();
    let mut paths = Vec::new();
    let mut urls = Vec::new();
    let mut suspicious = Vec::new();

    let shell_patterns = [
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "system(",
        "exec(",
        "popen(",
        "execve(",
    ];
    let suspicious_keywords = [
        "password",
        "secret",
        "token",
        "admin",
        "root",
        "login",
        "access denied",
        "flag{",
        "CTF{",
        "key=",
        "debug",
    ];

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.len() < 4 {
            continue;
        }

        // Shell / command strings
        if shell_patterns.iter().any(|p| trimmed.contains(p)) {
            shell.push(trimmed.to_string());
            continue;
        }

        // Format strings (contains %s, %p, %x, %n, %d with context suggesting printf-style)
        if trimmed.contains('%')
            && ["%s", "%p", "%x", "%n", "%d", "%lx", "%08x"]
                .iter()
                .any(|p| trimmed.contains(p))
        {
            format_strings.push(trimmed.to_string());
            continue;
        }

        // URLs
        if trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("ftp://")
        {
            urls.push(trimmed.to_string());
            continue;
        }

        // File paths
        if (trimmed.starts_with('/') && trimmed.len() > 2 && trimmed.contains('/'))
            || trimmed.starts_with("./")
            || trimmed.starts_with("../")
        {
            paths.push(trimmed.to_string());
            continue;
        }

        // Suspicious keywords
        let lower = trimmed.to_lowercase();
        if suspicious_keywords
            .iter()
            .any(|kw| lower.contains(&kw.to_lowercase()))
        {
            suspicious.push(trimmed.to_string());
        }
    }

    StringsInfo {
        shell,
        format_strings,
        paths,
        urls,
        suspicious,
    }
}

fn parse_ldd(output: &str) -> Libraries {
    // ldd output looks like:
    //   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7ffff7dd0000)
    //   /lib64/ld-linux-x86-64.so.2 (0x7ffff7fce000)
    let mut items = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("not a dynamic executable") {
            continue;
        }

        if trimmed.contains("=>") {
            // libc.so.6 => /lib/.../libc.so.6 (0x7ffff7dd0000)
            let parts: Vec<&str> = trimmed.splitn(2, "=>").collect();
            let name = parts[0].trim().to_string();
            let rest = parts.get(1).unwrap_or(&"").trim();

            let (path, base) = if let Some(paren_pos) = rest.find('(') {
                let path = rest[..paren_pos].trim().to_string();
                let base = rest[paren_pos..]
                    .trim_matches(|c| c == '(' || c == ')')
                    .trim()
                    .to_string();
                (path, base)
            } else {
                (rest.to_string(), String::new())
            };

            items.push(Library {
                name,
                path,
                runtime_base: base,
            });
        } else if let Some(paren_pos) = trimmed.find('(') {
            // /lib64/ld-linux-x86-64.so.2 (0x7ffff7fce000)
            let path = trimmed[..paren_pos].trim().to_string();
            let base = trimmed[paren_pos..]
                .trim_matches(|c| c == '(' || c == ')')
                .trim()
                .to_string();
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();

            items.push(Library {
                name,
                path,
                runtime_base: base,
            });
        }
    }

    Libraries {
        source: "ldd".to_string(),
        items,
    }
}

fn parse_dynamic_entries(output: &str) -> DynamicInfo {
    // readelf -d output looks like:
    //  Tag        Type                         Name/Value
    //  0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
    //  0x000000000000000c (INIT)               0x401000
    let mut needed = Vec::new();
    let mut entries = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Tag") || trimmed.starts_with("Dynamic") {
            continue;
        }

        // Extract tag from parentheses
        if let (Some(open), Some(close)) = (trimmed.find('('), trimmed.find(')')) {
            let tag = trimmed[open + 1..close].trim().to_string();

            let value = trimmed[close + 1..].trim().to_string();

            // Extract NEEDED libraries
            if tag == "NEEDED" {
                if let (Some(lb), Some(rb)) = (value.find('['), value.find(']')) {
                    needed.push(value[lb + 1..rb].to_string());
                }
            }

            entries.push(DynamicEntry { tag, value });
        }
    }

    DynamicInfo { needed, entries }
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
