use crate::report::{DangerousFunction, Disassembly, SuspiciousFunction, Symbols};

fn extract_function_block(disasm: &str, func_name: &str) -> String {
    let mut result = String::new();
    let mut capturing = false;
    let marker = format!("<{}>:", func_name);
    let max_lines = 60;
    let mut count = 0;

    for line in disasm.lines() {
        if line.contains(&marker) {
            capturing = true;
            result.push_str(line);
            result.push('\n');
            count += 1;
            continue;
        }

        if capturing {
            if (line.ends_with(">:") && !line.contains(&marker)) || count >= max_lines {
                break;
            }
            result.push_str(line);
            result.push('\n');
            count += 1;
        }
    }

    result
}

pub fn parse_disassembly(objdump_output: &str, entry_point: &str) -> Disassembly {
    let entry = if !entry_point.is_empty() {
        let block = extract_function_block(objdump_output, "_start");
        if block.is_empty() {
            let addr_clean = entry_point.trim_start_matches("0x");
            let mut result = String::new();
            let mut capturing = false;
            let mut count = 0;
            for line in objdump_output.lines() {
                if !capturing && line.contains(addr_clean) && line.contains(">:") {
                    capturing = true;
                }
                if capturing {
                    if count > 0 && line.contains(">:") {
                        break;
                    }
                    result.push_str(line);
                    result.push('\n');
                    count += 1;
                    if count >= 40 {
                        break;
                    }
                }
            }
            result
        } else {
            block
        }
    } else {
        String::new()
    };

    let main = extract_function_block(objdump_output, "main");

    let suspicious_names = [
        "vuln",
        "vulnerable",
        "win",
        "backdoor",
        "secret",
        "shell",
        "flag",
        "exploit",
        "overflow",
        "hack",
        "pwn",
        "ret2",
    ];

    let mut suspicious_functions = Vec::new();
    for line in objdump_output.lines() {
        if line.contains(">:") {
            for name in &suspicious_names {
                if line.to_lowercase().contains(name) {
                    let func_name = line
                        .split('<')
                        .nth(1)
                        .unwrap_or("")
                        .split('>')
                        .next()
                        .unwrap_or("")
                        .to_string();

                    let addr = line.split_whitespace().next().unwrap_or("").to_string();
                    let disasm = extract_function_block(objdump_output, &func_name);

                    suspicious_functions.push(SuspiciousFunction {
                        name: func_name,
                        address: format!("0x{addr}"),
                        disassembly: disasm,
                    });
                    break;
                }
            }
        }
    }

    Disassembly {
        entry,
        main,
        suspicious_functions,
    }
}

const DANGEROUS_FUNCTIONS: &[(&str, &str)] = &[
    ("gets", "unbounded input, likely buffer overflow"),
    ("strcpy", "possible overflow, no bounds checking"),
    ("strcat", "possible overflow, no bounds checking"),
    ("sprintf", "possible overflow, no bounds checking"),
    ("scanf", "risky if %s is used without width"),
    ("vsprintf", "possible overflow, no bounds checking"),
    ("printf", "possible format string if user-controlled"),
    ("fprintf", "possible format string if user-controlled"),
    ("snprintf", "safer but still check format string usage"),
    ("system", "command execution primitive"),
    ("execve", "command execution primitive"),
    ("execvp", "command execution primitive"),
    ("popen", "command execution primitive"),
    ("malloc", "useful for heap analysis"),
    ("free", "useful for heap analysis, double-free potential"),
    ("realloc", "useful for heap analysis"),
    ("read", "potential for overflow if size unchecked"),
    ("recv", "potential for overflow if size unchecked"),
    ("mmap", "memory mapping, potential for shellcode"),
    ("mprotect", "can change memory permissions"),
];

pub fn detect_dangerous_functions(
    symbols: &Symbols,
    objdump_output: &str,
) -> Vec<DangerousFunction> {
    let mut found = Vec::new();

    for import in &symbols.imports {
        for (name, risk) in DANGEROUS_FUNCTIONS {
            if import.name == *name {
                found.push(DangerousFunction {
                    name: import.name.clone(),
                    risk: risk.to_string(),
                    location: format!("import (PLT: {})", import.plt_address),
                });
                break;
            }
        }
    }

    for line in objdump_output.lines() {
        if !line.contains("call") && !line.contains("callq") {
            continue;
        }

        for (name, risk) in DANGEROUS_FUNCTIONS {
            let plt_ref = format!("<{}@plt>", name);
            let direct_ref = format!("<{}>", name);

            if line.contains(&plt_ref) || line.contains(&direct_ref) {
                let caller = find_caller_function(objdump_output, line);

                if !found
                    .iter()
                    .any(|f| f.name == *name && f.location.contains(&caller))
                {
                    found.push(DangerousFunction {
                        name: name.to_string(),
                        risk: risk.to_string(),
                        location: caller,
                    });
                }
                break;
            }
        }
    }

    found
}

fn find_caller_function(objdump_output: &str, target_line: &str) -> String {
    let mut current_func = String::from("unknown");

    for line in objdump_output.lines() {
        if line.contains(">:") {
            current_func = line
                .split('<')
                .nth(1)
                .unwrap_or("")
                .split('>')
                .next()
                .unwrap_or("unknown")
                .to_string();
        }
        if std::ptr::eq(line, target_line) || line == target_line {
            return current_func;
        }
    }

    current_func
}
