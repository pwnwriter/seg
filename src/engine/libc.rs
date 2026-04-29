use std::collections::HashMap;

use crate::report::{Libraries, LibcInfo, LibcMatch, LibcRip, LocalLibc, Symbols};

const LIBC_RIP_ENDPOINT: &str = "https://libc.rip/api/find";

const USEFUL_SYMBOLS: &[&str] = &[
    "system",
    "puts",
    "printf",
    "__libc_start_main",
    "str_bin_sh",
];

pub fn resolve_libc(libraries: &Libraries, symbols: &Symbols) -> LibcInfo {
    let local = extract_local_libc(libraries);
    let libc_rip = query_libc_rip(symbols);

    LibcInfo { local, libc_rip }
}

fn extract_local_libc(libraries: &Libraries) -> LocalLibc {
    for lib in &libraries.items {
        if lib.name.contains("libc.so") {
            return LocalLibc {
                source: "ldd".to_string(),
                path: lib.path.clone(),
                runtime_base: lib.runtime_base.clone(),
            };
        }
    }

    LocalLibc {
        source: String::new(),
        path: String::new(),
        runtime_base: String::new(),
    }
}

fn query_libc_rip(symbols: &Symbols) -> LibcRip {
    // Pick a known function to query with — prefer puts, printf, or __libc_start_main
    let leak_candidates = ["puts", "printf", "write", "__libc_start_main"];

    let mut query_symbols: HashMap<String, String> = HashMap::new();
    for import in &symbols.imports {
        if leak_candidates.contains(&import.name.as_str()) && !import.got_address.is_empty() {
            query_symbols.insert(import.name.clone(), import.got_address.clone());
        }
    }

    if query_symbols.is_empty() {
        return LibcRip {
            enabled: false,
            endpoint: LIBC_RIP_ENDPOINT.to_string(),
            query: serde_json::Value::Null,
            matches: vec![],
            useful_symbols: HashMap::new(),
        };
    }

    let query_body = serde_json::json!({
        "symbols": &query_symbols,
    });

    let result = ureq::post(LIBC_RIP_ENDPOINT)
        .header("Content-Type", "application/json")
        .send_json(&query_body);

    let response = match result {
        Ok(mut resp) => match resp.body_mut().read_json::<serde_json::Value>() {
            Ok(v) => v,
            Err(_) => {
                return LibcRip {
                    enabled: true,
                    endpoint: LIBC_RIP_ENDPOINT.to_string(),
                    query: query_body,
                    matches: vec![],
                    useful_symbols: HashMap::new(),
                };
            }
        },
        Err(_) => {
            return LibcRip {
                enabled: true,
                endpoint: LIBC_RIP_ENDPOINT.to_string(),
                query: query_body,
                matches: vec![],
                useful_symbols: HashMap::new(),
            };
        }
    };

    let mut matches = Vec::new();
    let mut useful_symbols = HashMap::new();

    if let Some(arr) = response.as_array() {
        for entry in arr {
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let build_id = entry
                .get("buildid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let download_url = entry
                .get("download_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Extract useful symbols from the first match
            if useful_symbols.is_empty() {
                if let Some(syms) = entry.get("symbols").and_then(|v| v.as_object()) {
                    for name in USEFUL_SYMBOLS {
                        if let Some(offset) = syms.get(*name).and_then(|v| v.as_str()) {
                            useful_symbols.insert(name.to_string(), offset.to_string());
                        }
                    }
                }
            }

            matches.push(LibcMatch {
                id,
                build_id,
                download_url,
            });
        }
    }

    LibcRip {
        enabled: true,
        endpoint: LIBC_RIP_ENDPOINT.to_string(),
        query: query_body,
        matches,
        useful_symbols,
    }
}
