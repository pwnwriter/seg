use crate::report::Protections;

pub fn parse_checksec(output: &str) -> Protections {
    let lower = output.to_lowercase();

    let pie = lower.contains("pie enabled");
    let nx = lower.contains("nx enabled");
    let canary = lower.contains("canary found") && !lower.contains("no canary found");
    let fortify = lower.contains("fortify") && !lower.contains("no fortify");

    let relro = if lower.contains("full relro") {
        "full".to_string()
    } else if lower.contains("partial relro") {
        "partial".to_string()
    } else if lower.contains("no relro") {
        "none".to_string()
    } else {
        String::new()
    };

    Protections {
        pie,
        nx,
        canary,
        relro,
        fortify,
    }
}
