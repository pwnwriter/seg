use crate::report::{
    DangerousFunction, ExploitationHints, LeakTarget, Protections, Strategy, Symbols,
};

pub fn derive_strategy(
    protections: &Protections,
    hints: &ExploitationHints,
    dangerous_functions: &[DangerousFunction],
    symbols: &Symbols,
) -> Strategy {
    let has_dangerous = |name: &str| dangerous_functions.iter().any(|f| f.name == name);
    let has_import = |name: &str| symbols.imports.iter().any(|i| i.name == name);

    // Build leak targets from imports that can leak libc addresses
    let leak_candidates = ["puts", "printf", "write", "read"];
    let leak_targets: Vec<LeakTarget> = symbols
        .imports
        .iter()
        .filter(|i| leak_candidates.contains(&i.name.as_str()) && !i.plt_address.is_empty())
        .map(|i| LeakTarget {
            symbol: i.name.clone(),
            got: i.got_address.clone(),
            plt: i.plt_address.clone(),
        })
        .collect();

    // Determine strategy based on what we know
    if has_dangerous("gets") || has_dangerous("strcpy") || has_dangerous("read") {
        if hints.shellcode_possible && !protections.nx {
            return Strategy {
                most_likely: "shellcode injection".to_string(),
                reason: "NX is disabled and a buffer overflow vector exists. Shellcode can be placed on the stack.".to_string(),
                steps: vec![
                    "Find overflow offset using cyclic pattern.".to_string(),
                    "Place shellcode in the buffer.".to_string(),
                    "Overwrite return address to point to shellcode.".to_string(),
                    "Spawn shell.".to_string(),
                ],
                leak_targets,
            };
        }

        if hints.ret2libc_possible {
            let mut steps = vec![
                "Find overflow offset using cyclic pattern.".to_string(),
            ];

            if !leak_targets.is_empty() {
                steps.push(format!(
                    "Leak {}@GOT using {}@PLT to get libc address.",
                    leak_targets[0].symbol, leak_targets[0].symbol
                ));
                steps.push("Compute libc base from leaked address.".to_string());
            }

            steps.push("Call system(\"/bin/sh\") using libc addresses.".to_string());

            return Strategy {
                most_likely: "ret2libc".to_string(),
                reason: "NX is enabled, no canary is present, and libc functions are imported.".to_string(),
                steps,
                leak_targets,
            };
        }

        if hints.rop_likely {
            return Strategy {
                most_likely: "ROP chain".to_string(),
                reason: "NX is enabled and no canary is present. ROP gadgets can be used to chain calls.".to_string(),
                steps: vec![
                    "Find overflow offset using cyclic pattern.".to_string(),
                    "Find ROP gadgets using ropper or ROPgadget.".to_string(),
                    "Build ROP chain to call execve or system.".to_string(),
                    "Send payload.".to_string(),
                ],
                leak_targets,
            };
        }

        // Simple ret2win if there's a win/shell/backdoor function
        let win_funcs: Vec<&str> = ["win", "shell", "backdoor", "flag"]
            .iter()
            .filter(|f| {
                symbols.exports.iter().any(|e| e.name.to_lowercase().contains(*f))
            })
            .copied()
            .collect();

        if !win_funcs.is_empty() {
            let target = symbols
                .exports
                .iter()
                .find(|e| win_funcs.iter().any(|w| e.name.to_lowercase().contains(w)))
                .unwrap();

            return Strategy {
                most_likely: "ret2win".to_string(),
                reason: format!(
                    "Buffer overflow exists and a target function '{}' is present at {}.",
                    target.name, target.address
                ),
                steps: vec![
                    "Find overflow offset using cyclic pattern.".to_string(),
                    format!("Overwrite return address with {} ({}).", target.name, target.address),
                    "Spawn shell.".to_string(),
                ],
                leak_targets,
            };
        }

        // Generic buffer overflow
        return Strategy {
            most_likely: "buffer overflow".to_string(),
            reason: "A buffer overflow vector was detected. Determine the exact exploitation path based on available gadgets and functions.".to_string(),
            steps: vec![
                "Find overflow offset using cyclic pattern.".to_string(),
                "Determine control of instruction pointer.".to_string(),
                "Identify available targets (win function, libc, ROP gadgets).".to_string(),
                "Build and send exploit payload.".to_string(),
            ],
            leak_targets,
        };
    }

    if hints.format_string_likely {
        let mut steps = vec![
            "Determine format string offset (e.g., AAAA%p%p%p...).".to_string(),
            "Leak stack/libc addresses using %p or %x.".to_string(),
        ];

        if hints.got_overwrite_possible && has_import("printf") {
            steps.push("Overwrite GOT entry using %n to redirect execution.".to_string());
            steps.push("Redirect to system or a win function.".to_string());

            return Strategy {
                most_likely: "format string GOT overwrite".to_string(),
                reason: "Format string vulnerability exists with partial/no RELRO, allowing GOT overwrite.".to_string(),
                steps,
                leak_targets,
            };
        }

        steps.push("Use leaked addresses to build further exploitation.".to_string());

        return Strategy {
            most_likely: "format string".to_string(),
            reason: "A format string vulnerability was detected.".to_string(),
            steps,
            leak_targets,
        };
    }

    // Heap exploitation
    if has_dangerous("malloc") && has_dangerous("free") {
        return Strategy {
            most_likely: "heap exploitation".to_string(),
            reason: "malloc/free are used, suggesting heap-based vulnerability (UAF, double-free, heap overflow).".to_string(),
            steps: vec![
                "Identify allocation/free patterns and potential UAF or double-free.".to_string(),
                "Control freed chunk metadata or function pointers.".to_string(),
                "Trigger reuse to overwrite target (function pointer, GOT, etc.).".to_string(),
                "Redirect execution to system or shellcode.".to_string(),
            ],
            leak_targets,
        };
    }

    Strategy {
        most_likely: String::new(),
        reason: "No clear exploitation path identified from automated analysis.".to_string(),
        steps: vec![],
        leak_targets,
    }
}
