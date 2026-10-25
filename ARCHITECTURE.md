# REO (Reverse Engineering Orchestrator) Architecture

## Overview

REO is a unified orchestration meta-layer that fuses **Ghidra** (deep C/C++ AST decompilation), **REA** (multi-target binary triage & dynamic instrumentation), and **ECC** (autonomous engineering harness & verification loops).

```
 ┌────────────────────────────────────────────────────────┐
 │      LLM Client (Claude Code / Cursor / Gemini)        │
 └───────────────────────────┬────────────────────────────┘
                             │
                  Clean MCP Protocol (5 Tools)
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │           REO (Reverse Engineering Orchestrator)       │
 ├────────────────────────────────────────────────────────┤
 │  • Autonomous 4-Phase SRE Pipeline                     │
 │  • Dynamic-Static Feedback Loop                        │
 │  • Context-Optimized Tool Routing                      │
 └─────────────┬────────────────────────────┬─────────────┘
               │                            │
               ▼                            ▼
      Ghidra Engine (GhidraMCP)         REA Engine
  (Deep C Decompiler & AST)        (Frida / Rizin / PE)
```

---

## The 4-Phase Autonomous Pipeline

### Phase 1: Ingestion & Auto-Triage (REA)
- Sniffs file magic bytes to determine format (`PE`, `ELF`, `Mach-O`, `APK`, `ASAR`, `WASM`, `Firmware`).
- Extracts architecture, bitness, endianness, protections, and key strings.

### Phase 2: Engine Binding & Session Setup
- Auto-detects if Ghidra GUI is open on loopback port `8080`.
- If running: attaches for live GUI synchronization.
- If offline: runs in-process via PyGhidra / Headless mode without blocking.

### Phase 3: The Decompile-Trace Feedback Loop
- Decompiles target functions using Ghidra's AST engine.
- If encrypted strings or indirect calls are detected, REO launches an isolated **Frida** or **Rizin** session via REA to trace parameters and decrypt memory buffers at runtime.
- **The Bridge**: The decrypted strings and observed types are automatically written back into Ghidra's project database via GhidraMCP (`set_decompiler_comment`, `rename_variable`, `set_function_prototype`).

### Phase 4: ECC Synthesis & Quality Verification
- Manages an **Obligation Ledger** tracking open hypotheses.
- Runs an automated security audit checking for memory corruption, buffer overflows, and hardcoded secrets.
- Synthesizes modern, idiomatic reconstructed source code.
