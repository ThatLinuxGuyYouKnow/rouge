![Rouge — autonomous red team](assets/rouge-banner.png)

# Rouge

**Prove it's safe. One exploit at a time.**

Rouge is an autonomous red-team agent that finds vulnerabilities, **proves them
exploitable, ranks them, and patches them** — end to end. Every finding is
treated as a hypothesis, not a conclusion: a vulnerability is real only when an
exploit fires, and a fix counts only when the exploit stops working.

## How it works

Four specialist agents, orchestrated with LangGraph over shared typed state:

| Agent | Role |
|---|---|
| **Recon** (the Scout) | Reads the target codebase, traces user input to dangerous sinks. Finds SQL injection, command injection, XSS, path traversal, SSRF, hardcoded credentials. |
| **Exploit** (the Rouge Agent) | Writes a real attack script for *each* finding and runs it against an isolated copy of the target. |
| **Triage** | Ranks confirmed issues by exploitability, impact, and exposure. |
| **Patch** (the Sentinel) | Rewrites the vulnerable function, then **re-runs the original exploit** against the patched code. |

A conditional edge routes to patch mode (`rouge fix`) or report mode
(`rouge scan --mode report`) after triage.

## Honest verdicts

Three states, not two. Anything that can't be tested is marked **UNVERIFIED** —
never silently counted as safe.

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | The exploit script exited cleanly and printed a `VULNERABLE:` verdict with output as evidence. |
| **FALSE POSITIVE** | Tested and blocked (`NOT_VULNERABLE:`), closed with proof. |
| **UNVERIFIED** | Couldn't be tested (missing dependency, timeout, unsafe script). |

Every scan ends in **VERT** (clean bill of health), a confirmed-findings report
with verified patches, or **INCOMPLETE** when findings exist that couldn't be
tested. A dependency pre-flight warns before the scan even starts.

## Quickstart

```bash
pip install -e .
rouge setup                  # pick a provider, paste a key, live-validated
rouge scan --mode report ./target
rouge fix ./target           # patch top finding, verify with re-exploit
rouge monitor --port 8765    # live dashboard: agent log, findings, verdicts
```

`rouge setup` saves to `~/.rouge/config.json` (mode `0600`). Override anytime
with `--model` / `--api-key` / `--api-base` or `ROUGE_MODEL` /
`ROUGE_API_KEY` / `ROUGE_API_BASE`.

## Providers

One LiteLLM client behind a clean interface — the same agent graph runs
unchanged on 100+ providers (Qwen default, OpenAI, Anthropic, Gemini, Groq,
OpenRouter, local Ollama, OpenCode Go). Bring the model; Rouge brings the
harness.

## Run it from your coding agent

Rouge ships as an agent skill (`opencode_skill/SKILL.md`): invoke scans from
inside your agentic coding workflow — every pull request, every late-night
refactor — instead of as a separate tool you forget to run.

## Safety model

Exploit scripts are authored by a model that just read untrusted third-party
source, so they are never trusted:

- **AST safety gate** — no network, subprocess, file writes, `eval`/`exec`.
- **Secrets scrubbed** from the environment before generated code runs.
- **Disposable snapshots** — scripts execute against a throwaway copy; your
  repo is never mutated.
- **Target-reference check** — a script that never touches the reported target
  cannot confirm anything (this killed the "exit code 0 means vulnerable" era).

Known limitation, stated in the code: this is guardrails, not a security
boundary. Real container isolation is on the roadmap.

## Project layout

```
rouge/
  graph.py        # LangGraph: nodes, conditional edge, VERT/INCOMPLETE logic
  client.py       # LiteLLM client (generate() interface)
  config.py       # provider presets, setup wizard persistence
  cli.py          # scan / fix / setup / monitor commands
  monitor.py      # aiohttp + SSE dashboard
  agents/
    recon.py      # candidate findings + dependency pre-flight
    exploit.py    # marker-protocol verification in snapshots
    triage.py     # rank-map ordering with severity fallback
    patch.py      # AST function surgery + re-exploit validation
    sandbox.py    # gate, env scrub, snapshots, execution
test_targets/     # deliberately vulnerable demo apps
demo_app/         # second demo target
opencode_skill/   # agent-skill packaging
```

## What's next

Container/microVM isolation, human-in-the-loop approval gates before patches
land, a GitHub Action that comments confirmed exploits on PRs, broader language
and vulnerability coverage, and hosted scanning for teams and classrooms.

## License

MIT — see [LICENSE](LICENSE).
