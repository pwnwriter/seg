use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub binary: BinaryInfo,
    pub metadata: FileMetadata,
    pub protections: Protections,
    pub elf: ElfInfo,
    pub libraries: Libraries,
    pub dynamic: DynamicInfo,
    pub symbols: Symbols,
    pub strings: StringsInfo,
    pub disassembly: Disassembly,
    pub dangerous_functions: Vec<DangerousFunction>,
    pub exploitation_hints: ExploitationHints,
    pub libc: LibcInfo,
    pub strategy: Strategy,
    pub ai_summary: AiSummary,
    pub raw_outputs: RawOutputs,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub command: String,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
pub struct BinaryInfo {
    pub path: String,
    pub name: String,
    pub file_type: String,
    pub architecture: String,
    pub bits: u32,
    pub endianness: String,
    pub interpreter: String,
    pub stripped: bool,
    pub is_static: bool,
    pub entry_point: String,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct FileMetadata {
    pub size_bytes: u64,
    pub permissions: String,
    pub owner: String,
    pub modified_time: String,
}

#[derive(Debug, Serialize)]
pub struct Protections {
    pub pie: bool,
    pub nx: bool,
    pub canary: bool,
    pub relro: String,
    pub fortify: bool,
}

#[derive(Debug, Serialize)]
pub struct ElfInfo {
    pub headers: ElfHeaders,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
}

#[derive(Debug, Serialize)]
pub struct ElfHeaders {
    pub elf_type: String,
    pub machine: String,
    pub abi: String,
}

#[derive(Debug, Serialize)]
pub struct Segment {
    pub seg_type: String,
    pub offset: String,
    pub virtual_address: String,
    pub size: String,
    pub permissions: String,
}

#[derive(Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub address: String,
    pub offset: String,
    pub size: String,
    pub flags: String,
}

#[derive(Debug, Serialize)]
pub struct Libraries {
    pub source: String,
    pub items: Vec<Library>,
}

#[derive(Debug, Serialize)]
pub struct Library {
    pub name: String,
    pub path: String,
    pub runtime_base: String,
}

#[derive(Debug, Serialize)]
pub struct DynamicInfo {
    pub needed: Vec<String>,
    pub entries: Vec<DynamicEntry>,
}

#[derive(Debug, Serialize)]
pub struct DynamicEntry {
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Symbols {
    pub imports: Vec<ImportedSymbol>,
    pub exports: Vec<ExportedSymbol>,
}

#[derive(Debug, Serialize)]
pub struct ImportedSymbol {
    pub name: String,
    pub library: String,
    pub plt_address: String,
    pub got_address: String,
}

#[derive(Debug, Serialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub address: String,
    pub sym_type: String,
}

#[derive(Debug, Serialize)]
pub struct StringsInfo {
    pub shell: Vec<String>,
    pub format_strings: Vec<String>,
    pub paths: Vec<String>,
    pub urls: Vec<String>,
    pub suspicious: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Disassembly {
    pub entry: String,
    pub main: String,
    pub suspicious_functions: Vec<SuspiciousFunction>,
}

#[derive(Debug, Serialize)]
pub struct SuspiciousFunction {
    pub name: String,
    pub address: String,
    pub disassembly: String,
}

#[derive(Debug, Serialize)]
pub struct DangerousFunction {
    pub name: String,
    pub risk: String,
    pub location: String,
}

#[derive(Debug, Serialize)]
pub struct ExploitationHints {
    pub buffer_overflow_likely: bool,
    pub format_string_likely: bool,
    pub ret2libc_possible: bool,
    pub got_overwrite_possible: bool,
    pub shellcode_possible: bool,
    pub rop_likely: bool,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LibcInfo {
    pub local: LocalLibc,
    pub libc_rip: LibcRip,
}

#[derive(Debug, Serialize)]
pub struct LocalLibc {
    pub source: String,
    pub path: String,
    pub runtime_base: String,
}

#[derive(Debug, Serialize)]
pub struct LibcRip {
    pub enabled: bool,
    pub endpoint: String,
    pub query: serde_json::Value,
    pub matches: Vec<LibcMatch>,
    pub useful_symbols: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct LibcMatch {
    pub id: String,
    pub build_id: String,
    pub download_url: String,
}

#[derive(Debug, Serialize)]
pub struct Strategy {
    pub most_likely: String,
    pub reason: String,
    pub steps: Vec<String>,
    pub leak_targets: Vec<LeakTarget>,
}

#[derive(Debug, Serialize)]
pub struct LeakTarget {
    pub symbol: String,
    pub got: String,
    pub plt: String,
}

#[derive(Debug, Serialize)]
pub struct AiSummary {
    pub one_line: String,
    pub important_facts: Vec<String>,
    pub recommended_path: String,
}

#[derive(Debug, Serialize)]
pub struct RawOutputs {
    pub file: String,
    pub stat: String,
    pub ldd: String,
    pub checksec: String,
    pub readelf: String,
    pub objdump: String,
    pub strings: String,
}
