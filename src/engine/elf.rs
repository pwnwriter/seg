use crate::report::{BinaryInfo, ElfHeaders, Section, Segment};

fn readelf_field(output: &str, key: &str) -> String {
    output
        .lines()
        .find(|l| l.contains(key))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

pub fn parse_readelf_headers(output: &str, binary: &mut BinaryInfo) -> ElfHeaders {
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

pub fn parse_readelf_segments(output: &str) -> Vec<Segment> {
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

pub fn parse_readelf_sections(output: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with('[') && line.contains(']') {
            let after_bracket = line.split(']').nth(1).unwrap_or("").trim();
            let parts: Vec<&str> = after_bracket.split_whitespace().collect();

            if parts.len() >= 4 {
                let name = parts[0].to_string();
                if name == "" || parts[1] == "NULL" {
                    i += 1;
                    continue;
                }

                let address = format!("0x{}", parts.get(2).unwrap_or(&""));
                let offset = format!("0x{}", parts.get(3).unwrap_or(&""));

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
