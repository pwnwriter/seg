use crate::report::{DangerousFunction, ExploitationHints, Protections, Symbols};

pub fn derive_hints(
    protections: &Protections,
    dangerous_functions: &[DangerousFunction],
    symbols: &Symbols,
) -> ExploitationHints {
    let mut reasoning = Vec::new();

    let has_dangerous = |name: &str| dangerous_functions.iter().any(|f| f.name == name);
    let has_import = |name: &str| symbols.imports.iter().any(|i| i.name == name);

    // Buffer overflow
    let buffer_overflow_likely = has_dangerous("gets")
        || has_dangerous("strcpy")
        || has_dangerous("strcat")
        || has_dangerous("sprintf")
        || has_dangerous("scanf")
        || has_dangerous("read")
        || has_dangerous("recv");

    if buffer_overflow_likely {
        let funcs: Vec<&str> = ["gets", "strcpy", "strcat", "sprintf", "scanf", "read", "recv"]
            .iter()
            .filter(|f| has_dangerous(f))
            .copied()
            .collect();
        reasoning.push(format!(
            "Dangerous functions detected: {}. Buffer overflow is likely.",
            funcs.join(", ")
        ));
    }

    // Format string
    let format_string_likely = has_dangerous("printf") || has_dangerous("fprintf");
    if format_string_likely {
        reasoning.push(
            "printf/fprintf detected. If user input reaches format string, format string attack is possible.".to_string()
        );
    }

    // NX
    let shellcode_possible = !protections.nx;
    if protections.nx {
        reasoning.push("NX is enabled, so injected shellcode is unlikely.".to_string());
    } else {
        reasoning.push(
            "NX is disabled, so shellcode injection onto the stack may be possible.".to_string(),
        );
    }

    // Canary
    if !protections.canary {
        reasoning.push(
            "No stack canary detected, so stack overflow exploitation may be easier.".to_string(),
        );
    } else {
        reasoning.push(
            "Stack canary is present. Overflow exploitation requires a canary leak or bypass."
                .to_string(),
        );
    }

    // RELRO / GOT overwrite
    let got_overwrite_possible = protections.relro != "full";
    if protections.relro == "full" {
        reasoning.push("Full RELRO means GOT is read-only. GOT overwrite is not possible.".to_string());
    } else if protections.relro == "partial" {
        reasoning.push(
            "Partial RELRO means GOT overwrite may be possible.".to_string(),
        );
    } else if protections.relro == "none" || protections.relro.is_empty() {
        reasoning.push("No RELRO detected. GOT overwrite is likely possible.".to_string());
    }

    // PIE
    if !protections.pie {
        reasoning.push("PIE is disabled, so binary addresses are stable and predictable.".to_string());
    } else {
        reasoning.push(
            "PIE is enabled. Binary base address is randomized; a leak is needed.".to_string(),
        );
    }

    // Ret2libc
    let has_libc_imports = has_import("puts")
        || has_import("printf")
        || has_import("write")
        || has_import("read");
    let ret2libc_possible = protections.nx && has_libc_imports && !protections.canary;
    if ret2libc_possible {
        let leak_funcs: Vec<&str> = ["puts", "printf", "write"]
            .iter()
            .filter(|f| has_import(f))
            .copied()
            .collect();
        reasoning.push(format!(
            "Imported {} can be used as libc leak target(s) for ret2libc.",
            leak_funcs.join(", ")
        ));
    }

    // ROP
    let rop_likely = protections.nx && !protections.canary;
    if rop_likely {
        reasoning.push(
            "NX enabled + no canary suggests ROP chain is the likely exploitation technique."
                .to_string(),
        );
    }

    ExploitationHints {
        buffer_overflow_likely,
        format_string_likely,
        ret2libc_possible,
        got_overwrite_possible,
        shellcode_possible,
        rop_likely,
        reasoning,
    }
}
