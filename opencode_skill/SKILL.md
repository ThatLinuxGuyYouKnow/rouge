---
name: rouge
description: Autonomous AI Red Team & Remediation Hive - find vulnerabilities, validate exploits, and generate patches
metadata:
  author: Project Rouge
  version: 0.2.0
---

# Rouge - Autonomous AI Red Team

Run `/rouge scan <path>` to autonomously scan a codebase for vulnerabilities, validate them with exploit tests, prioritize findings, and generate verified patches.

## Setup

Before running any rouge command, ensure the package is installed. Run the setup block below once:

```bash
ROUGE_VENV="$HOME/.rouge-venv"
test -d "$ROUGE_VENV" || python3 -m venv "$ROUGE_VENV"
$ROUGE_VENV/bin/pip install -e /home/alabi-ayobami/rouge
```

After setup, run commands with `$ROUGE_VENV/bin/rouge` or `$ROUGE_VENV/bin/python -m rouge`.

## Commands

### `/rouge scan <target_path>`
Full autonomous pipeline:
1. **Recon Agent** scans source code for potential vulnerabilities (SQLi, XSS, command injection, path traversal)
2. **Exploit Agent** generates and runs local exploit tests to confirm real vulnerabilities
3. **Triage Agent** prioritizes confirmed vulnerabilities by severity
4. **Patch Agent** generates fixes and re-validates to ensure the patch works

### `/rouge scan --mode fix <target_path>`
Default mode. Full autonomous pipeline with patch generation.

### `/rouge scan --mode report <target_path>`
Generates a detailed markdown report with findings, exploit code, exploit output, and LLM-generated remediation recommendations for each confirmed vulnerability. Copies false positives with reasons for rejection. Saves to `target/rouge_reports/rouge_report_*.md`.

### `/rouge scan --backend zen <target_path>`
Use the **zen** backend (opencode.ai) instead of the default **qwen** backend. Combine with `--mode` as needed. Every scan also writes an agent log file to `target/rouge_logs/rouge_log_*.md` capturing all agent phase messages and results.

When no vulnerabilities are confirmed, the scan returns a **VERT — Clean Bill of Health**.

### `/rouge fix <target_path> <function_name> <vuln_type>`
Generate and validate a patch for a specific vulnerability.

### `/rouge monitor`
Starts the **Monitoring Station** — a local web dashboard that streams agent logs in real time as scans run.

```bash
$ROUGE_VENV/bin/rouge monitor
# optionally: --port 8765 --open
```

Open the printed URL (default `http://localhost:8765`) to:
- Launch a scan with a chosen target path, mode (fix/report), and backend (zen/qwen)
- Watch every agent phase message stream in live (recon -> exploit -> triage -> patch/report)
- See the live summary (findings / confirmed / false positives) and a **VERT** badge on a clean scan
- Click through to the generated report and agent log files

The dashboard uses Server-Sent Events (SSE); late-joining clients automatically receive the full history of the current/last scan.

## Usage

Always run setup first, then use `$ROUGE_VENV/bin/rouge` for all commands.

```bash
# Setup (once)
ROUGE_VENV="$HOME/.rouge-venv"
test -d "$ROUGE_VENV" || python3 -m venv "$ROUGE_VENV"
$ROUGE_VENV/bin/pip install -e /home/alabi-ayobami/rouge

# Scan
$ROUGE_VENV/bin/rouge scan <target>
# or: $ROUGE_VENV/bin/python -m rouge scan <target>

# Fix
$ROUGE_VENV/bin/rouge fix <path> <function> <type>
# or: $ROUGE_VENV/bin/python -m rouge fix <path> <function> <type>
```

## Output

- **Reports:** `target/rouge_reports/rouge_report_*.md` — full markdown security report (report mode)
- **Logs:** `target/rouge_logs/rouge_log_*.md` — agent phase log + results summary (every scan)
- **VERT:** When no vulnerabilities are confirmed, the scan returns a clean bill of health.

## Environment

Requires `DASHSCOPE_API_KEY` set in the environment for the qwen backend. The senpai MCP already configures this. The zen backend uses a built-in key by default.
