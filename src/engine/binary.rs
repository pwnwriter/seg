use crate::report::{BinaryInfo, FileMetadata};

pub fn parse_file_output(output: &str, path: &str, name: &str, sha256: &str) -> BinaryInfo {
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
        entry_point: String::new(),
        sha256: sha256.to_string(),
    }
}

pub fn parse_stat_output(output: &str) -> FileMetadata {
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
