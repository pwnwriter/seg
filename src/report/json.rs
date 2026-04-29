use crate::report::Report;

pub fn render(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| {
        format!("{{\"error\": \"failed to serialize report: {e}\"}}")
    })
}
