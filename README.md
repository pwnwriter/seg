# [`seg`](https://github.com/pwnwriter/seg)
`Analyze. Understand. Exploit binaries` || [`seg`](https://github.com/pwnwriter/seg/),&nbsp; A CLI tool that gives you **actionable binary intelligence** in one command. Point it at any ELF binary and get a full recon report — protections, dangerous functions, symbols with PLT/GOT addresses, disassembly highlights, libc resolution, and a suggested exploit strategy. Built for [`CTF players`](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)), [`pentesters`](https://en.wikipedia.org/wiki/Penetration_test), and [`AI agents`](https://en.wikipedia.org/wiki/Intelligent_agent).

No more running 7 tools and cross-referencing output manually. One command. Full picture. 🦀

<p align="left">

<a href="https://github.com/pwnwriter/seg/releases"><img src="https://img.shields.io/github/v/release/pwnwriter/seg?style=flat&amp;labelColor=56534b&amp;color=c1c1b6&amp;logo=GitHub&amp;logoColor=white" alt="GitHub Release"></a>
<a href="https://crates.io/crates/seg/"><img src="https://img.shields.io/crates/v/seg?style=flat&amp;labelColor=56534b&amp;color=c1c1b6&amp;logo=Rust&amp;logoColor=white" alt="Crate Release"></a>
<a href="https://github.com/pwnwriter/seg/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-white.svg" alt="MIT LICENSE"></a>
[![ko-fi](https://img.shields.io/badge/support-pwnwriter%20-pink?logo=kofi&logoColor=white)](https://ko-fi.com/pwnwriter)

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## Table of contents

* [`Features`](#features)
* [`Installation`](#installation)
* [`Usage`](#usage)
  * [`Analyze`](#usage-analyze)
  * [`Invoke`](#usage-invoke)
  * [`Hook`](#usage-hook)
* [`Report Sections`](#report-sections)
* [`Tools Used`](#tools-used)
* [`Contribution`](#contribution)
* [`Support`](#support)
* [`Also see`](#see)
* [`License`](#license)

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

<a name="features"></a>
## Features

- **One command recon**: Run `seg analyze ./binary` and get everything — protections, symbols, strings, disassembly, exploit strategy.
- **Dual output**: `--markdown` for humans, `--json` for AI agents and automation pipelines.
- **Dangerous function detection**: Flags `gets`, `strcpy`, `system`, `printf` and 17 more risky functions with call-site locations.
- **Exploit strategy**: Automatically suggests ret2libc, ret2win, format string, shellcode, ROP, or heap exploitation based on what it finds.
- **Libc resolution**: Extracts local libc from `ldd` and queries [libc.rip](https://libc.rip) for remote libc matching with useful offsets (`system`, `str_bin_sh`, etc.).
- **Disassembly highlights**: Pulls out `main`, `_start`, and suspiciously named functions (`vuln`, `win`, `backdoor`, `shell`, etc.).
- **String categorization**: Separates shell commands, format strings, file paths, URLs, and suspicious strings.
- **Function invocation**: Call exported functions from shared libraries at runtime using `dlopen`/`dlsym`/`libffi`, or call functions by address using `ptrace`.
- **Function hooking**: Hook libc/imported functions using `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS) with auto-generated C hooks.
- **Portable**: Written in Rust. Wraps standard Linux tools you already have.
  
<a name="Todo"></a>
## TODO (pls help)

- [x] `seg invoke`: call exported functions from shared libraries using `dlopen`, `dlsym`, and `libffi`.
- [x] `seg invoke --addr`: call functions inside ELF binaries by address using debugger-assisted execution.
- [x] `seg hook`: hook libc/imported functions using `LD_PRELOAD`.
- [ ] `seg hook --frida`: runtime hooks using Frida later.

  References: https://youtu.be/0o8Ex8mXigU?si=Qq60LRr5jUB_nnwR

<a name="installation"></a>
## Installation

<details> <summary><code>🌼 Source</code></summary>
&nbsp;

```bash
git clone --depth=1 https://github.com/pwnwriter/seg --branch=main
cd seg
cargo build --release
```

Binary will be at `target/release/seg`. Move it to your `$PATH`.
</details>

<details> <summary><code>🎠 Cargo</code></summary>
&nbsp;

```bash
cargo install seg
```
</details>

<details> <summary><code>❄️ Nix</code></summary>
&nbsp;

```bash
nix run github:pwnwriter/seg
```
</details>

### Requirements

`seg` wraps these standard Linux tools (most are pre-installed):

| Tool | Package | Purpose |
|---|---|---|
| `file` | coreutils | Binary type detection |
| `stat` | coreutils | File metadata |
| `strings` | binutils | String extraction |
| `readelf` | binutils | ELF headers, sections, segments, symbols |
| `objdump` | binutils | Disassembly, PLT/GOT resolution |
| `ldd` | glibc | Linked library detection |
| `checksec` | checksec | Security protections |
| `cc` | gcc/clang | Compiling hook libraries (`seg hook`) |
| `libffi` | libffi-dev | FFI calling convention (`seg invoke`) |

Missing tools won't crash `seg` — they degrade gracefully and report what couldn't be gathered.

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

<a name="usage"></a>
## Usage

```
╔═╝╔═╝╔═╝
══║╔═╝║ ║
══╝══╝══╝ v0.1.0
    Analyze. Understand. Exploit binaries
                @pwnwriter/seg
```

<a name="usage-analyze"></a>
### Analyze

- <details> <summary><code> Markdown report to stdout </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --markdown
  ```
</details>

- <details> <summary><code> Markdown report to file </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --markdown report.md
  ```
</details>

- <details> <summary><code> JSON report to stdout </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --json
  ```
</details>

- <details> <summary><code> JSON report to file </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --json report.json
  ```
</details>

- <details> <summary><code> Both formats at once </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --markdown report.md --json report.json
  ```
</details>

- <details> <summary><code> Short aliases </code></summary>
  &nbsp;

  ```bash
  seg ana ./vuln --json
  seg analy ./vuln --markdown
  ```
</details>

- <details> <summary><code> Pipe JSON to jq </code></summary>
  &nbsp;

  ```bash
  seg analyze ./vuln --json | jq '.strategy'
  seg analyze ./vuln --json | jq '.dangerous_functions'
  seg analyze ./vuln --json | jq '.exploitation_hints'
  ```
</details>

<a name="usage-invoke"></a>
### Invoke

- <details> <summary><code> Call a function from a shared library </code></summary>
  &nbsp;

  ```bash
  seg invoke ./libmath.so add --ret i32 -- i32:2 i32:3
  ```
</details>

- <details> <summary><code> Call a function that returns a string </code></summary>
  &nbsp;

  ```bash
  seg invoke ./libgreet.so greet --ret string
  ```
</details>

- <details> <summary><code> Call a function by address (Linux, ptrace) </code></summary>
  &nbsp;

  ```bash
  seg invoke ./vuln --addr 0x401234 --ret i32 -- i32:42
  ```
</details>

<a name="usage-hook"></a>
### Hook

- <details> <summary><code> Log calls to a function </code></summary>
  &nbsp;

  ```bash
  seg hook ./vuln puts --action log
  ```
</details>

- <details> <summary><code> Replace a function with your own </code></summary>
  &nbsp;

  ```bash
  seg hook ./vuln rand --action replace --replace-lib ./fake_rand.so
  ```
</details>

- <details> <summary><code> Pass arguments to the target binary </code></summary>
  &nbsp;

  ```bash
  seg hook ./vuln gets --action log -- AAAAAAAAAA
  ```
</details>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
<a name="report-sections"></a>

## Report Sections

<details>
<summary><code>📊 View Report Sections</code></summary>

&nbsp;

| # | Section | Description |
|---|---|---|
| 1 | Summary | Binary path, type, arch, bits, endianness |
| 2 | Security Protections | PIE, NX, Canary, RELRO, Fortify |
| 3 | File Metadata | Size, permissions, owner, SHA256 |
| 4 | ELF Headers | Entry point, machine, ABI |
| 5 | Program Segments | LOAD, INTERP, etc. with permissions |
| 6 | Sections | .text, .plt, .got, .bss, etc. |
| 7 | Linked Libraries | Shared libraries from `ldd` |
| 8 | Dynamic Entries | NEEDED, INIT, FINI, etc. |
| 9 | Imported Functions | Name, library, PLT address, GOT address |
| 10 | Exported Symbols | Name, address, type |
| 11 | Interesting Strings | Shell, format strings, paths, URLs, suspicious |
| 12 | Disassembly Highlights | Entry point, main, suspicious functions |
| 13 | Dangerous Functions | gets, strcpy, system, printf, etc. with risk + location |
| 14 | Exploitation Hints | Buffer overflow, format string, ret2libc, ROP |
| 15 | Libc Information | Local libc + libc.rip matching |
| 16 | Suggested Strategy | Most likely exploit path with step-by-step |
| 17 | AI Agent Summary | One-line summary for automation |
| 18 | Raw Tool Outputs | Unprocessed output from all tools |

</details>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

<a name="tools-used"></a>
## How it works

`seg` is a **wrapper and analyzer** — it runs standard binary analysis tools, parses their output, cross-references the results, and generates structured intelligence:

```
Binary ──→ file, stat, readelf, objdump, strings, ldd, checksec
               │
               ▼
         Parse & Cross-reference
               │
               ▼
    Dangerous functions + Exploitation hints + Strategy
               │
               ▼
       Markdown (human) / JSON (machine)
```

The JSON output is designed to be consumed directly by AI agents, exploit scripts, or automation pipelines. Every address, every symbol, every protection status is structured and queryable.

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

<a name="contribution"></a>
## Contribution

Contributions are welcome! You can suggest features, report bugs, fix issues via [issues](https://github.com/pwnwriter/seg/issues) or [pull requests](https://github.com/pwnwriter/seg/pulls). Help with code, documentation, and spreading the word about `seg` is appreciated!

### Building test binaries

```bash
# Compile sample vulnerable binaries for testing
./tests/compile.sh

# Run seg against them
seg analyze ./tests/bins/bof_basic --markdown
seg analyze ./tests/bins/fmt_string --json
seg analyze ./tests/bins/ret2libc --json | jq '.strategy'
seg analyze ./tests/bins/heap_uaf --json | jq '.dangerous_functions'
```

<a name="support"></a>
## Support

I am a student currently attending university. I like working for *Open Source* in my free time. If you find my tool or work beneficial, please consider supporting me via [*KO-FI*](https://ko-fi.com/pwnwriter) by leaving a star; I'll appreciate your action :)

<a name="see"></a>
## Also see
- [`Haylxon`](https://github.com/pwnwriter/haylxon) :- A blazingly fast tool to grab screenshots of webpages from terminal
- [`Kanha`](https://github.com/pwnwriter/kanha) :- A web-app pentesting suite written in Rust
- [`checksec`](https://github.com/slimm609/checksec.sh) :- Bash script to check binary security properties
- [`pwntools`](https://github.com/Gallopsled/pwntools) :- CTF framework and exploit development library
- [`binsider`](https://github.com/orhun/binsider) :- Analyze ELF binaries like a boss 😼🕵️‍♂️

<a name="license"></a>
## License
Licensed under the [**`MIT LICENSE`**](/LICENSE)

<p align="center"><img src="https://raw.githubusercontent.com/catppuccin/catppuccin/main/assets/footers/gray0_ctp_on_line.svg?sanitize=true" /></p>
<p align="center">Copyright &copy; 2026 - present <a href="https://pwnwriter.me" target="_blank"> pwnwriter me </a></p>
