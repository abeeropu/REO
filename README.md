# ⚡ REO: Reverse Engineering Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io/)

> **The Autonomous SRE Conductor** — Orchestrating **Ghidra**, **REA**, and **ECC** into a single unified AI reverse engineering pipeline.

```
                              ┌─────────────────────────┐
                              │    User: "Analyze"      │
                              └────────────┬────────────┘
                                           │
                                           ▼
                 ╔════════════════════════════════════════════════╗
                 ║     REO (Reverse Engineering Orchestrator)     ║
                 ╚════════════════════════════════════════════════╝
                                           │
          ┌────────────────────────────────┼────────────────────────────────┐
          ▼                                ▼                                ▼
   ┌──────────────┐                 ┌──────────────┐                 ┌──────────────┐
   │     REA      │                 │    Ghidra    │                 │     ECC      │
   │ (rea-agents) │                 │ (GhidraMCP)  │                 │ (Agent Core) │
   ├──────────────┤                 ├──────────────┤                 ├──────────────┤
   │ Multi-Format │                 │ NSA Deep C   │                 │ Verification │
   │ Triage &     │                 │ Decompiler,  │                 │ Loops &      │
   │ Frida Tracing│                 │ AST & Structs│                 │ Security QA  │
   └──────────────┘                 └──────────────┘                 └──────────────┘
```

---

## 🎯 Why REO?

Modern AI-assisted reverse engineering has three incredible powerhouses:
1. **[Ghidra](https://github.com/NationalSecurityAgency/ghidra)** (NSA): The undisputed king of deep C/C++ AST decompilation, type recovery, and cross-reference indexing.
2. **[REA](https://github.com/morluto/rea)**: The multi-format Swiss Army knife with 200+ tools covering PE, ELF, Mach-O, Android APKs, Electron, and dynamic instrumentation (Frida, Rizin, GDB).
3. **[ECC](https://github.com/affaan-m/ECC)**: The premier autonomous harness providing verification loops, Obligation Ledgers, and security review checklists.

### The Problem REO Solves:
* **The 238-Tool Token Bloat**: Exposing 238 raw tools overwhelms LLM context windows, draining tokens and leading to tool hallucination.
* **The Static vs. Dynamic Silo**: Ghidra decompiler has no idea what Frida dynamically decrypts in REA.
* **Too Many Questions**: Other tools require the user to choose disassemblers, configure ports, and manage dependencies manually.

**REO is the conductor.** One command or prompt, and REO coordinates the engines autonomously—decompile with Ghidra, trace with REA, verify with ECC, and synchronize live comments back into Ghidra's database!

---

## 🚀 Quickstart

### 1. Autonomous CLI Analysis
Reverse engineer any binary, APK, or firmware file directly:

```bash
# Autonomous end-to-end analysis with Markdown report
npx reo-sre analyze crackme.exe -o report.md
```

### 2. Run Diagnostics
Check that Java 25, Ghidra, GhidraMCP, and REA are properly connected:

```bash
npx reo-sre doctor
```

### 3. Orchestrated Engine Update
Because REO orchestrates Ghidra, REA, GhidraMCP, and ECC, `reo update` automatically checks and updates all 4 engines and dependencies in a single run:

```bash
# Check status across all 4 engines without updating
npx reo-sre update --check

# Automatically update REO, REA, GhidraMCP, and ECC
npx reo-sre update

# Or update a specific engine
npx reo-sre update rea
npx reo-sre update ghidramcp
npx reo-sre update ecc
```

---

## 🔌 Using REO with AI Coding Assistants (MCP Server)

REO exposes a **Meta-MCP server** that condenses 238 raw tools into **high-leverage autonomous tools**:

| Tool | Description |
| :--- | :--- |
| `reo_analyze` | End-to-end autonomous analysis (triage, decompile, trace, and synthesize). |
| `reo_decompile` | Deep C/C++ AST decompilation with callers and variable types. |
| `reo_trace_and_annotate` | Frida dynamic trace that writes decrypted values directly back into Ghidra decompiler. |
| `reo_update` | Autonomous multi-engine updater (updates REA, GhidraMCP, ECC, and REO on demand). |
| `reo_doctor` | Self-diagnostic check for local reverse engineering prerequisites. |

### Configuration

Add REO to your client's MCP configuration:

#### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "reo": {
      "command": "npx",
      "args": ["-y", "reo-sre", "serve"]
    }
  }
}
```

#### Claude Code (`~/.claude.json` or CLI)
```bash
claude mcp add reo -- npx -y reo-sre serve
```

#### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "reo": {
      "command": "npx",
      "args": ["-y", "reo-sre", "serve"]
    }
  }
}
```

#### Gemini CLI & Antigravity (`~/.gemini/config/mcp_config.json`)
```json
{
  "mcpServers": {
    "reo": {
      "command": "npx",
      "args": ["-y", "reo-sre", "serve"]
    }
  }
}
```

---

## 🔄 The Static-Dynamic Feedback Loop

When REO analyzes a protected binary:
1. **Ghidra** decompiles the function and flags an obfuscated buffer.
2. **REA** spins up a lightweight Frida hook to observe the routine at runtime and grab the decrypted memory.
3. **REO's Bridge** immediately calls Ghidra's `set_decompiler_comment` and `rename_variable` to write the decrypted strings straight into your Ghidra GUI window!

---

## 🛠️ Requirements & Prerequisites

REO works out of the box with built-in format sniffers, but connects automatically to:
- **Java 25+** (Required by Ghidra 12.2)
- **Ghidra 12.2** (`$GHIDRA_INSTALL_DIR`)
- **GhidraMCP** (Ghidra extension listening on port 8080)
- **REA** (`rea-agents` npm package)
- **Node.js** >= 18.0.0

Run `reo doctor` at any time to verify your environment.

---

## 📜 License

MIT © [Abeer Opu](https://github.com/abeeropu)
