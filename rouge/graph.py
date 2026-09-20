from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from .client import get_client
from .config import current_model
from .agents import recon, exploit, triage, patch
import os
import operator
import datetime


class RougeState(TypedDict):
    target_path: str
    mode: str
    findings: list[dict]
    confirmed: list[dict]
    inconclusive: list[dict]
    prioritized: list[dict]
    top_vuln: dict | None
    patch_result: dict | None
    report_path: str
    log_path: str
    log: Annotated[list[str], operator.add]
    phase: str


async def recon_node(state: RougeState) -> dict:
    client = get_client()
    log = [f"[Recon] Scanning {state['target_path']} for vulnerabilities..."]
    findings, warnings = await recon.recon_scan(state["target_path"], client)
    log.append(f"[Recon] Found {len(findings)} potential vulnerabilities")
    for f in findings:
        log.append(f"  - [{f['type']}] {f['file']}:{f['line']} in {f['function']}")
    log.extend(warnings)
    return {"findings": findings, "log": log, "phase": "exploit"}


async def exploit_node(state: RougeState) -> dict:
    client = get_client()
    log = [f"[Exploit] Validating {len(state['findings'])} findings..."]
    confirmed = []
    inconclusive = []

    for finding in state["findings"]:
        log.append(f"[Exploit] Testing: {finding['function']} ({finding['type']})...")
        result = await exploit.run_exploit(finding, client)
        verdict = result.get("verification", "inconclusive")
        if verdict == "confirmed":
            confirmed.append(result)
            log.append(f"  CONFIRMED: {finding['type']} in {finding['function']}")
        elif verdict == "negative":
            log.append(f"  REJECTED (tested, not exploitable): {finding['type']} in {finding['function']}")
        else:
            inconclusive.append(result)
            log.append(f"  UNVERIFIED: {finding['type']} in {finding['function']} — {result.get('verification_reason', 'unknown')}")

    return {"confirmed": confirmed, "inconclusive": inconclusive, "log": log, "phase": "triage"}


async def triage_node(state: RougeState) -> dict:
    client = get_client()
    log = [f"[Triage] Prioritizing {len(state['confirmed'])} confirmed vulns..."]
    sorted_vulns, top = await triage.triage_prioritize(state["confirmed"], client)

    if top:
        log.append(
            f"[Triage] Top priority: {top['type']} in {top['function']} "
            f"({top['file']}:{top['line']})"
        )
    else:
        log.append("[Triage] No vulnerabilities to prioritize.")

    return {"prioritized": sorted_vulns, "top_vuln": top, "log": log, "phase": "route"}


def route_after_triage(state: RougeState) -> str:
    if state.get("mode") == "report":
        return "report"
    return "patch"


REPORT_REMEDIATION_SYSTEM = """You are a security consultant. Given a confirmed vulnerability, write a clear remediation recommendation for a developer.

Include:
1. Why this is dangerous (1-2 sentences)
2. The specific fix needed (code-level)

Keep it under 200 words. Be direct and technical. No markdown headers."""


async def report_node(state: RougeState) -> dict:
    client = get_client()
    log = ["[Report] Generating comprehensive security report..."]

    confirmed = state.get("confirmed", [])
    findings = state.get("findings", [])
    inconclusive = state.get("inconclusive", [])
    target = state["target_path"]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    decided_funcs = {c.get("function") for c in confirmed}
    decided_funcs |= {c.get("function") for c in inconclusive}
    false_positives = [f for f in findings if f.get("function") not in decided_funcs]

    lines = []
    lines.append(f"# Rouge Security Report")
    lines.append(f"")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**Model:** {current_model()}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total findings | {len(findings)} |")
    lines.append(f"| Confirmed | {len(confirmed)} |")
    lines.append(f"| False positives | {len(false_positives)} |")
    lines.append(f"| Unverified (inconclusive) | {len(inconclusive)} |")
    lines.append(f"")

    severity_order = {"critical": 0, "high": 1, "medium": 2}

    if confirmed:
        lines.append(f"## Confirmed Vulnerabilities")
        lines.append(f"")
        for i, vuln in enumerate(confirmed, 1):
            sev = vuln.get("severity", "medium").upper()
            vtype = vuln["type"].replace("_", " ").title()
            lines.append(f"### {i}. [{sev}] {vtype}")
            lines.append(f"")
            lines.append(f"**Location:** `{vuln['file']}:{vuln['line']}` in `{vuln['function']}()`")
            lines.append(f"")
            lines.append(f"**Description:** {vuln.get('description', 'N/A')}")
            lines.append(f"")

            if vuln.get("exploit_code"):
                lines.append(f"<details>")
                lines.append(f"<summary>Exploit Code</summary>")
                lines.append(f"")
                lines.append(f"```python")
                lines.append(f"{vuln['exploit_code']}")
                lines.append(f"```")
                lines.append(f"</details>")
                lines.append(f"")

            if vuln.get("exploit_output"):
                lines.append(f"<details>")
                lines.append(f"<summary>Exploit Output</summary>")
                lines.append(f"")
                lines.append(f"```")
                lines.append(f"{vuln['exploit_output'][:500]}")
                lines.append(f"```")
                lines.append(f"</details>")
                lines.append(f"")

            log.append(f"[Report] Getting remediation for {vuln['function']} ({vuln['type']})...")
            try:
                user_msg = f"""Vulnerability: {vuln['type']} in {vuln['function']}()
Description: {vuln.get('description', '')}
Code snippet:
```python
{vuln.get('code_snippet', vuln.get('description', ''))}
```
Exploit: {vuln.get('exploit_output', '')[:200]}"""

                remediation = await client.generate(
                    system_prompt=REPORT_REMEDIATION_SYSTEM,
                    user_message=user_msg,
                    max_tokens=600,
                    temperature=0.3,
                )
                vuln["remediation"] = remediation
            except Exception:
                vuln["remediation"] = "_Remediation generation failed_"

            lines.append(f"**Remediation:**")
            lines.append(f"")
            lines.append(f"{vuln.get('remediation', 'N/A')}")
            lines.append(f"")

            lines.append(f"---")
            lines.append(f"")

    if false_positives:
        lines.append(f"## False Positives (Rejected)")
        lines.append(f"")
        for fp in false_positives:
            vtype = fp["type"].replace("_", " ").title()
            lines.append(f"- **{vtype}** in `{fp['function']}()` — `{fp['file']}:{fp['line']}`: {fp.get('description', '')[:120]}")
        lines.append(f"")

    if inconclusive:
        lines.append(f"## Unverified (Inconclusive — NOT proven safe)")
        lines.append(f"")
        lines.append(f"These findings could not be tested to a verdict. They must "
                     f"not be read as clean — re-run with dependencies installed "
                     f"or review them manually.")
        lines.append(f"")
        for inc in inconclusive:
            vtype = str(inc.get("type", "?")).replace("_", " ").title()
            lines.append(f"- **{vtype}** in `{inc.get('function', '?')}()` — "
                         f"`{inc.get('file', '?')}:{inc.get('line', '?')}`: "
                         f"{inc.get('verification_reason', 'unknown')[:200]}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"_Report generated by [Project Rouge](https://github.com) — Autonomous AI Red Team & Remediation Hive_")
    lines.append(f"")

    report_content = "\n".join(lines)

    report_dir = os.path.join(target, "rouge_reports")
    os.makedirs(report_dir, exist_ok=True)
    report_filename = f"rouge_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(report_dir, report_filename)

    with open(report_path, "w") as f:
        f.write(report_content)

    log.append(f"[Report] Saved to {report_path}")

    return {"report_path": report_path, "log": log, "phase": "done"}


async def patch_node(state: RougeState) -> dict:
    if not state.get("top_vuln"):
        return {"log": ["[Patch] No vulnerability selected for patching."], "phase": "done"}

    client = get_client()
    vuln = state["top_vuln"]
    log = [f"[Patch] Generating fix for {vuln['type']} in {vuln['function']}..."]

    result = await patch.generate_and_validate_patch(vuln, client)

    if result:
        log.append(f"[Patch] Fix validated after {result['attempts']} attempt(s)")
        log.append(f"[Patch] Changes: {result['changes_summary'][:200]}")
    else:
        log.append("[Patch] Failed to generate validated patch after retries.")

    return {"patch_result": result, "log": log, "phase": "done"}


def build_graph():
    graph = StateGraph(RougeState)

    graph.add_node("recon", recon_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("triage", triage_node)
    graph.add_node("patch", patch_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "exploit")
    graph.add_edge("exploit", "triage")
    graph.add_conditional_edges("triage", route_after_triage, {
        "patch": "patch",
        "report": "report",
    })
    graph.add_edge("patch", END)
    graph.add_edge("report", END)

    return graph.compile()


async def run_rouge(target_path: str, mode: str = "fix") -> RougeState:
    graph = build_graph()
    initial_state: RougeState = {
        "target_path": os.path.abspath(target_path),
        "mode": mode,
        "findings": [],
        "confirmed": [],
        "inconclusive": [],
        "prioritized": [],
        "top_vuln": None,
        "patch_result": None,
        "report_path": "",
        "log_path": "",
        "log": [],
        "phase": "recon",
    }
    state = await graph.ainvoke(initial_state)
    state["log_path"] = _write_log_file(state)
    return state


def _write_log_file(state: RougeState) -> str:
    target = state.get("target_path", ".")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    findings = state.get("findings", [])
    confirmed = state.get("confirmed", [])
    inconclusive = state.get("inconclusive", [])
    decided_funcs = {c.get("function") for c in confirmed}
    decided_funcs |= {c.get("function") for c in inconclusive}
    false_positives = [f for f in findings if f.get("function") not in decided_funcs]

    lines = []
    lines.append("# Rouge Scan Log")
    lines.append("")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Mode:** {state.get('mode', 'fix')}")
    lines.append(f"**Model:** {current_model()}")
    lines.append(f"**Timestamp:** {timestamp}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Agent Phase Log")
    lines.append("")
    for msg in state.get("log", []):
        lines.append(f"- {msg}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(f"- Total findings: {len(findings)}")
    lines.append(f"- Confirmed vulnerabilities: {len(confirmed)}")
    lines.append(f"- False positives: {len(false_positives)}")
    lines.append(f"- Unverified (inconclusive): {len(inconclusive)}")
    lines.append("")

    if confirmed:
        lines.append("### Confirmed Vulnerabilities")
        lines.append("")
        for v in confirmed:
            vtype = v["type"].replace("_", " ").title()
            lines.append(f"- **{vtype}** in `{v['function']}()` — `{v['file']}:{v['line']}`")
        lines.append("")

    if false_positives:
        lines.append("### False Positives")
        lines.append("")
        for fp in false_positives:
            vtype = fp["type"].replace("_", " ").title()
            lines.append(f"- **{vtype}** in `{fp['function']}()` — `{fp['file']}:{fp['line']}`")
        lines.append("")

    if inconclusive:
        lines.append("### Unverified (Inconclusive)")
        lines.append("")
        for inc in inconclusive:
            vtype = str(inc.get("type", "?")).replace("_", " ").title()
            lines.append(f"- **{vtype}** in `{inc.get('function', '?')}()` — "
                         f"{inc.get('verification_reason', 'unknown')[:150]}")
        lines.append("")

    if not confirmed and not inconclusive:
        lines.append("> **VERT** — Clean bill of health. No exploitable vulnerabilities found.")
        lines.append("")
    elif not confirmed:
        lines.append(f"> **INCOMPLETE** — No vulnerability was confirmed, but "
                     f"{len(inconclusive)} finding(s) could not be verified. "
                     f"This is NOT a clean bill of health.")
        lines.append("")

    log_content = "\n".join(lines)

    log_dir = os.path.join(target, "rouge_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_filename = f"rouge_log_{stamp}.md"
    log_path = os.path.join(log_dir, log_filename)

    with open(log_path, "w") as f:
        f.write(log_content)

    return log_path
