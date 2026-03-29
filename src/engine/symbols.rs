use std::collections::HashMap;

use crate::report::{ExportedSymbol, ImportedSymbol, Symbols};

pub fn parse_symbols(dynsym_output: &str, plt_output: &str, got_output: &str) -> Symbols {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    // Build PLT address map from objdump -d -j .plt
    let mut plt_map: HashMap<String, String> = HashMap::new();
    for line in plt_output.lines() {
        if line.contains("@plt>:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr) = parts.first() {
                let name = line
                    .split('<')
                    .nth(1)
                    .unwrap_or("")
                    .split('@')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    plt_map.insert(name, format!("0x{addr}"));
                }
            }
        }
    }

    // Build GOT address map from objdump -R
    let mut got_map: HashMap<String, String> = HashMap::new();
    for line in got_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            let addr = format!("0x{}", parts[0]);
            let sym_name = parts
                .last()
                .unwrap_or(&"")
                .split('@')
                .next()
                .unwrap_or("")
                .to_string();
            if !sym_name.is_empty() {
                got_map.insert(sym_name, addr);
            }
        }
    }

    // Parse readelf --dyn-syms
    for line in dynsym_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Symbol") || trimmed.starts_with("Num:") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }

        let value = parts[1];
        let sym_type = parts[3];
        let ndx = parts[6];
        let full_name = parts[7..].join(" ");
        let name = full_name.split('@').next().unwrap_or("").to_string();

        if name.is_empty() {
            continue;
        }

        if ndx == "UND" {
            let library = full_name
                .split('@')
                .nth(1)
                .unwrap_or("")
                .split(|c: char| c == ' ' || c == '(')
                .next()
                .unwrap_or("")
                .to_string();

            imports.push(ImportedSymbol {
                name: name.clone(),
                library,
                plt_address: plt_map.get(&name).cloned().unwrap_or_default(),
                got_address: got_map.get(&name).cloned().unwrap_or_default(),
            });
        } else if sym_type == "FUNC" || sym_type == "OBJECT" {
            exports.push(ExportedSymbol {
                name,
                address: format!("0x{value}"),
                sym_type: sym_type.to_string(),
            });
        }
    }

    Symbols { imports, exports }
}
