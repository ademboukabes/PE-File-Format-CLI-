#  pecli 

`pecli` is a powerful, premium-styled command-line tool designed for deep analysis of Windows Portable Executable (PE) files. It is built for reverse engineers, malware analysts, and CTF players who need quick, actionable insights into binary files.

---

##  Installation

To install `pecli` locally in development mode:

```bash
# Clone the repository and navigate to the folder
cd PE-File-Format-CLI-

# Install the package
pip install -e .
```

Once installed, you can use the `pecli` command directly from your terminal.

---

## 📖 Command Reference

### 1️⃣ `pecli info` — The First Look
**Goal**: Get a quick high-level overview of the binary.

```bash
pecli info path/to/sample.exe
```

- **What it shows**: Architecture (x86/x64), Entry Point, Number of sections, Global Entropy, and a Suspicion of Packing flag.
- **When to use**: This is always your first command. It tells you if the file is worth opening in a heavy disassembler like IDA or Ghidra, or if it's likely packed.

### 2️⃣ `pecli headers` — Structure Analysis
**Goal**: Inspect the core PE headers.

```bash
pecli headers path/to/sample.exe --dos       # View DOS Header (MZ)
pecli headers path/to/sample.exe --file      # View File Header (Machine, Sections, etc.)
pecli headers path/to/sample.exe --optional  # View Optional Header (Entry Point, ImageBase)
```

- **Usage**: Check for fake timestamps, non-standard Entry Points, or suspicious Subsystems.

### 3️⃣ `pecli sections` — Packing & Obfuscation Detection
**Goal**: Analyze section headers, permissions, and entropy.

```bash
pecli sections path/to/sample.exe --entropy --suspicious
```

- **What it shows**: Virtual vs Raw sizes, Permissions (R/W/X), and Entropy per section.
- **Red Flags**:
  - **RWX Sections**: Very rare in legitimate code; common in shellcode loaders.
  - **High Entropy (> 7.5)**: Indicates compressed or encrypted data (likely packed).
  - **Suspicious Names**: Sections named `.vmp`, `.upx`, or randomized strings.

### 4️⃣ `pecli imports` — Behavioral Insights
**Goal**: See which DLLs and APIs the program uses.

```bash
pecli imports path/to/sample.exe --suspicious # Only show "dangerous" APIs
pecli imports path/to/sample.exe --dll-only   # Quick list of dependencies
```

- **Red Flags**:
  - **Suspicious APIs**: `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` (Classic process injection).
  - **Few Imports**: If a large program only imports `GetProcAddress` and `LoadLibraryA`, it’s definitely packed.

### 5️⃣ `pecli scan` — Automated Malware Triage
**Goal**: Get an automated "Verdict" based on heuristics.

```bash
pecli scan path/to/sample.exe
pecli scan path/to/sample.exe --json > result.json
```

- **What it does**: Combines entropy analysis, section checks, and API monitoring to calculate a **Suspicion Score (0-100)**.
- **Automation**: Use the `--json` flag to integrate `pecli` into SOC pipelines or automated scripts.

---

## 🧪 Real-World Use Cases

### 🔍 Reverse Engineering
Before diving into code, run `pecli info` and `pecli sections` to understand the layout and find where the actual code starts.

### 😈 Malware Analysis
Detect loaders and droppers by running `pecli scan`. If you see a high score and APIs like `CreateProcessA` or `ShellExecuteA`, you know the binary is intended to launch other payloads.

### 🚩 CTF (Capture The Flag)
Quickly find hidden data in non-standard sections or identify if a challenge is just a UPX-packed executable that needs to be unpacked first.

---

## 🏗 Project Structure

```text
pecli/
├── main.py          # Entry point
├── core/
│   ├── analyzer.py  # Orchestration logic
│   └── context.py   # PE state & RVA-to-Offset conversion
├── pe/
│   ├── dos.py       # DOS & MZ Header
│   ├── headers.py   # NT Headers & Data Directories
│   ├── sections.py  # Section table
│   └── imports.py   # Import table parser
├── analysis/
│   ├── entropy.py   # Shannon entropy algorithm
│   └── heuristics.py# Security rules & scoring
└── cli/             # Rich-based UI modules
```

---

## 🏁 Summary Table

| Command | Role |
| :--- | :--- |
| **info** | Global view (is it packed?) |
| **headers** | Structural integrity |
| **sections** | Detect obfuscation |
| **imports**| Behavior (what does it do?) |
| **scan** | Quick decision / Automation |
