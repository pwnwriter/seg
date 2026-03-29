use crate::report::{DynamicEntry, DynamicInfo, Libraries, Library};

pub fn parse_ldd(output: &str) -> Libraries {
    let mut items = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.contains("not a dynamic executable") {
            continue;
        }

        if trimmed.contains("=>") {
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

pub fn parse_dynamic_entries(output: &str) -> DynamicInfo {
    let mut needed = Vec::new();
    let mut entries = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Tag") || trimmed.starts_with("Dynamic") {
            continue;
        }

        if let (Some(open), Some(close)) = (trimmed.find('('), trimmed.find(')')) {
            let tag = trimmed[open + 1..close].trim().to_string();
            let value = trimmed[close + 1..].trim().to_string();

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
