use colored::Colorize;

pub fn splash() -> String {
    let version = env!("CARGO_PKG_VERSION");

    let logo = format!(
        r#"
╔═╝╔═╝╔═╝
══║╔═╝║ ║
══╝══╝══╝ v{}
    Analyze. Understand. Exploit binaries
                @pwnwriter/seg
 "#,
        version
    )
    .purple();

    format!("{logo}")
}
