use crate::report::Report;
use std::fmt::Write;

pub fn render(report: &Report) -> String {
    let mut md = String::new();

    // 1. Summary
    writeln!(md, "# seg Report: {}\n", report.binary.name).unwrap();
    writeln!(md, "> Actionable binary intelligence for exploitation.\n").unwrap();
    writeln!(md, "## 1. Summary\n").unwrap();
    writeln!(md, "- Binary: `{}`", report.binary.path).unwrap();
    writeln!(md, "- File Type: `{}`", report.binary.file_type).unwrap();
    writeln!(md, "- Architecture: `{}`", report.binary.architecture).unwrap();
    writeln!(md, "- Bits: `{}`", report.binary.bits).unwrap();
    writeln!(md, "- Endianness: `{}`", report.binary.endianness).unwrap();
    writeln!(md, "- Interpreter: `{}`", report.binary.interpreter).unwrap();
    writeln!(md, "- Stripped: `{}`", report.binary.stripped).unwrap();
    writeln!(md, "- Static Binary: `{}`", report.binary.is_static).unwrap();
    writeln!(md, "- Timestamp: `{}`", report.tool.generated_at).unwrap();

    // 2. Security Protections
    writeln!(md, "\n## 2. Security Protections\n").unwrap();
    writeln!(md, "| Protection | Status |").unwrap();
    writeln!(md, "|---|---|").unwrap();
    writeln!(md, "| PIE | {} |", bool_status(report.protections.pie)).unwrap();
    writeln!(md, "| NX | {} |", bool_status(report.protections.nx)).unwrap();
    writeln!(
        md,
        "| Stack Canary | {} |",
        bool_status(report.protections.canary)
    )
    .unwrap();
    writeln!(
        md,
        "| RELRO | {} |",
        if report.protections.relro.is_empty() {
            "unknown"
        } else {
            &report.protections.relro
        }
    )
    .unwrap();
    writeln!(
        md,
        "| Fortify | {} |",
        bool_status(report.protections.fortify)
    )
    .unwrap();

    // 3. File Metadata
    writeln!(md, "\n## 3. File Metadata\n").unwrap();
    writeln!(md, "| Field | Value |").unwrap();
    writeln!(md, "|---|---|").unwrap();
    writeln!(md, "| Size | {} bytes |", report.metadata.size_bytes).unwrap();
    writeln!(md, "| Permissions | {} |", report.metadata.permissions).unwrap();
    writeln!(md, "| Owner | {} |", report.metadata.owner).unwrap();
    writeln!(md, "| Modified | {} |", report.metadata.modified_time).unwrap();
    writeln!(md, "| SHA256 | `{}` |", report.binary.sha256).unwrap();

    // 4. ELF Headers
    writeln!(md, "\n## 4. ELF Headers\n").unwrap();
    writeln!(md, "- Entry Point: `{}`", report.binary.entry_point).unwrap();
    writeln!(md, "- Machine: `{}`", report.elf.headers.machine).unwrap();
    writeln!(md, "- ELF Type: `{}`", report.elf.headers.elf_type).unwrap();
    writeln!(md, "- ABI: `{}`", report.elf.headers.abi).unwrap();

    // 5. Program Segments
    if !report.elf.segments.is_empty() {
        writeln!(md, "\n## 5. Program Segments\n").unwrap();
        writeln!(
            md,
            "| Type | Offset | Virtual Address | Size | Permissions |"
        )
        .unwrap();
        writeln!(md, "|---|---|---|---|---|").unwrap();
        for seg in &report.elf.segments {
            writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                seg.seg_type, seg.offset, seg.virtual_address, seg.size, seg.permissions
            )
            .unwrap();
        }
    }

    // 6. Sections
    if !report.elf.sections.is_empty() {
        writeln!(md, "\n## 6. Sections\n").unwrap();
        writeln!(md, "| Name | Address | Offset | Size | Flags |").unwrap();
        writeln!(md, "|---|---|---|---|---|").unwrap();
        for sec in &report.elf.sections {
            writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                sec.name, sec.address, sec.offset, sec.size, sec.flags
            )
            .unwrap();
        }
    }

    // 7. Linked Libraries
    if !report.libraries.items.is_empty() {
        writeln!(md, "\n## 7. Linked Libraries\n").unwrap();
        writeln!(md, "Source: `{}`\n", report.libraries.source).unwrap();
        writeln!(md, "| Library | Path | Runtime Base |").unwrap();
        writeln!(md, "|---|---|---|").unwrap();
        for lib in &report.libraries.items {
            writeln!(md, "| {} | {} | {} |", lib.name, lib.path, lib.runtime_base).unwrap();
        }
    }

    // 8. Dynamic Entries
    if !report.dynamic.entries.is_empty() {
        writeln!(md, "\n## 8. Dynamic Entries\n").unwrap();
        writeln!(md, "| Tag | Value |").unwrap();
        writeln!(md, "|---|---|").unwrap();
        for entry in &report.dynamic.entries {
            writeln!(md, "| {} | {} |", entry.tag, entry.value).unwrap();
        }
    }

    // 9. Imported Functions
    if !report.symbols.imports.is_empty() {
        writeln!(md, "\n## 9. Imported Functions\n").unwrap();
        writeln!(md, "| Function | Library | PLT Address | GOT Address |").unwrap();
        writeln!(md, "|---|---|---|---|").unwrap();
        for imp in &report.symbols.imports {
            writeln!(
                md,
                "| {} | {} | {} | {} |",
                imp.name, imp.library, imp.plt_address, imp.got_address
            )
            .unwrap();
        }
    }

    // 10. Exported Symbols
    if !report.symbols.exports.is_empty() {
        writeln!(md, "\n## 10. Exported Symbols\n").unwrap();
        writeln!(md, "| Symbol | Address | Type |").unwrap();
        writeln!(md, "|---|---|---|").unwrap();
        for exp in &report.symbols.exports {
            writeln!(md, "| {} | {} | {} |", exp.name, exp.address, exp.sym_type).unwrap();
        }
    }

    // 11. Interesting Strings
    writeln!(md, "\n## 11. Interesting Strings\n").unwrap();
    render_string_section(&mut md, "Shell / Command Strings", &report.strings.shell);
    render_string_section(&mut md, "Format Strings", &report.strings.format_strings);
    render_string_section(&mut md, "File Paths", &report.strings.paths);
    render_string_section(&mut md, "URLs / Network Indicators", &report.strings.urls);
    render_string_section(
        &mut md,
        "Other Suspicious Strings",
        &report.strings.suspicious,
    );

    // 12. Disassembly Highlights
    writeln!(md, "\n## 12. Disassembly Highlights\n").unwrap();
    if !report.disassembly.entry.is_empty() {
        writeln!(md, "### Entry Point\n").unwrap();
        writeln!(md, "```asm\n{}```\n", report.disassembly.entry).unwrap();
    }
    if !report.disassembly.main.is_empty() {
        writeln!(md, "### Main Function\n").unwrap();
        writeln!(md, "```asm\n{}```\n", report.disassembly.main).unwrap();
    }
    for func in &report.disassembly.suspicious_functions {
        writeln!(md, "### {} ({})\n", func.name, func.address).unwrap();
        writeln!(md, "```asm\n{}```\n", func.disassembly).unwrap();
    }

    // 13. Dangerous Function Usage
    if !report.dangerous_functions.is_empty() {
        writeln!(md, "\n## 13. Dangerous Function Usage\n").unwrap();
        writeln!(md, "| Function | Location | Risk |").unwrap();
        writeln!(md, "|---|---|---|").unwrap();
        for df in &report.dangerous_functions {
            writeln!(md, "| {} | {} | {} |", df.name, df.location, df.risk).unwrap();
        }
    }

    // 14. Exploitation Hints
    writeln!(md, "\n## 14. Exploitation Hints\n").unwrap();
    writeln!(
        md,
        "- Buffer Overflow Likely: `{}`",
        report.exploitation_hints.buffer_overflow_likely
    )
    .unwrap();
    writeln!(
        md,
        "- Format String Likely: `{}`",
        report.exploitation_hints.format_string_likely
    )
    .unwrap();
    writeln!(
        md,
        "- Ret2libc Possible: `{}`",
        report.exploitation_hints.ret2libc_possible
    )
    .unwrap();
    writeln!(
        md,
        "- GOT Overwrite Possible: `{}`",
        report.exploitation_hints.got_overwrite_possible
    )
    .unwrap();
    writeln!(
        md,
        "- Shellcode Possible: `{}`",
        report.exploitation_hints.shellcode_possible
    )
    .unwrap();
    writeln!(
        md,
        "- ROP Likely Needed: `{}`",
        report.exploitation_hints.rop_likely
    )
    .unwrap();

    if !report.exploitation_hints.reasoning.is_empty() {
        writeln!(md, "\n### Reasoning\n").unwrap();
        for reason in &report.exploitation_hints.reasoning {
            writeln!(md, "- {reason}").unwrap();
        }
    }

    // 15. Libc Information
    if !report.libc.local.path.is_empty() || report.libc.libc_rip.enabled {
        writeln!(md, "\n## 15. Libc Information\n").unwrap();
        if !report.libc.local.path.is_empty() {
            writeln!(md, "### Local libc\n").unwrap();
            writeln!(md, "- Path: `{}`", report.libc.local.path).unwrap();
            writeln!(md, "- Runtime Base: `{}`", report.libc.local.runtime_base).unwrap();
        }
        if !report.libc.libc_rip.matches.is_empty() {
            writeln!(md, "\n### libc.rip Matches\n").unwrap();
            writeln!(md, "| ID | Build ID | Download URL |").unwrap();
            writeln!(md, "|---|---|---|").unwrap();
            for m in &report.libc.libc_rip.matches {
                writeln!(md, "| {} | {} | {} |", m.id, m.build_id, m.download_url).unwrap();
            }
        }
        if !report.libc.libc_rip.useful_symbols.is_empty() {
            writeln!(md, "\n### Useful libc Symbols\n").unwrap();
            writeln!(md, "| Symbol | Offset |").unwrap();
            writeln!(md, "|---|---|").unwrap();
            for (sym, offset) in &report.libc.libc_rip.useful_symbols {
                writeln!(md, "| {} | {} |", sym, offset).unwrap();
            }
        }
    }

    // 16. Suggested Exploit Strategy
    if !report.strategy.most_likely.is_empty() {
        writeln!(md, "\n## 16. Suggested Exploit Strategy\n").unwrap();
        writeln!(md, "### Most Likely Strategy\n").unwrap();
        writeln!(md, "`{}`\n", report.strategy.most_likely).unwrap();
        writeln!(md, "### Reason\n").unwrap();
        writeln!(md, "{}\n", report.strategy.reason).unwrap();
        if !report.strategy.steps.is_empty() {
            writeln!(md, "### Suggested Steps\n").unwrap();
            for (i, step) in report.strategy.steps.iter().enumerate() {
                writeln!(md, "{}. {step}", i + 1).unwrap();
            }
        }
    }

    // 17. AI Agent Summary
    writeln!(md, "\n## 17. AI Agent Summary\n").unwrap();
    writeln!(md, "```text").unwrap();
    writeln!(
        md,
        "Binary is {} {}-bit.",
        report.binary.architecture, report.binary.bits
    )
    .unwrap();
    writeln!(
        md,
        "Protections: PIE={}, NX={}, Canary={}, RELRO={}.",
        report.protections.pie,
        report.protections.nx,
        report.protections.canary,
        if report.protections.relro.is_empty() {
            "unknown"
        } else {
            &report.protections.relro
        }
    )
    .unwrap();
    if !report.exploitation_hints.reasoning.is_empty() {
        writeln!(md, "Key findings:").unwrap();
        for reason in &report.exploitation_hints.reasoning {
            writeln!(md, "  - {reason}").unwrap();
        }
    }
    writeln!(md, "```").unwrap();

    // 18. Raw Tool Outputs
    writeln!(md, "\n## 18. Raw Tool Outputs\n").unwrap();
    render_raw_output(&mut md, "file", &report.raw_outputs.file);
    render_raw_output(&mut md, "stat", &report.raw_outputs.stat);
    render_raw_output(&mut md, "ldd", &report.raw_outputs.ldd);
    render_raw_output(&mut md, "checksec", &report.raw_outputs.checksec);
    render_raw_output(&mut md, "readelf", &report.raw_outputs.readelf);
    render_raw_output(&mut md, "objdump", &report.raw_outputs.objdump);
    render_raw_output(
        &mut md,
        "strings (excerpt)",
        &truncate_strings(&report.raw_outputs.strings),
    );

    md
}

fn bool_status(v: bool) -> &'static str {
    if v { "enabled" } else { "disabled" }
}

fn render_string_section(md: &mut String, title: &str, items: &[String]) {
    writeln!(md, "### {title}\n").unwrap();
    if items.is_empty() {
        writeln!(md, "_None found._\n").unwrap();
    } else {
        writeln!(md, "```text").unwrap();
        for item in items {
            writeln!(md, "{item}").unwrap();
        }
        writeln!(md, "```\n").unwrap();
    }
}

fn render_raw_output(md: &mut String, tool: &str, output: &str) {
    writeln!(md, "### {tool}\n").unwrap();
    if output.trim().is_empty() {
        writeln!(md, "_No output._\n").unwrap();
    } else {
        writeln!(md, "```text\n{}```\n", output).unwrap();
    }
}

fn truncate_strings(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    if lines.len() <= 200 {
        return output.to_string();
    }
    let mut result: String = lines[..200].join("\n");
    writeln!(result, "\n... ({} more lines truncated)", lines.len() - 200).unwrap();
    result
}
