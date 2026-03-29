use crate::report::StringsInfo;

pub fn parse_strings(output: &str) -> StringsInfo {
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

        if shell_patterns.iter().any(|p| trimmed.contains(p)) {
            shell.push(trimmed.to_string());
            continue;
        }

        if trimmed.contains('%')
            && ["%s", "%p", "%x", "%n", "%d", "%lx", "%08x"]
                .iter()
                .any(|p| trimmed.contains(p))
        {
            format_strings.push(trimmed.to_string());
            continue;
        }

        if trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("ftp://")
        {
            urls.push(trimmed.to_string());
            continue;
        }

        if (trimmed.starts_with('/') && trimmed.len() > 2 && trimmed.contains('/'))
            || trimmed.starts_with("./")
            || trimmed.starts_with("../")
        {
            paths.push(trimmed.to_string());
            continue;
        }

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
