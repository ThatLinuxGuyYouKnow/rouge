import ast
import importlib.util
import json
import os
import sys
from pathlib import Path
from ..client import get_client

RECON_SYSTEM = """You are a security code reviewer (The Scout Agent) specializing in identifying vulnerabilities in Python web applications.

You will be given the COMPLETE source code of a project. Analyze ALL files together to understand the full picture — how functions are called, how data flows between modules, and where user input enters the system.

Focus on finding:
- SQL Injection (f-strings or string concatenation in SQL queries)
- Command Injection (os.system, os.popen, subprocess with user-controlled input)
- Cross-Site Scripting / XSS (unescaped user input in HTML/HTTP responses)
- Path Traversal (user-controlled file paths without sanitization)
- Hardcoded credentials (passwords, API keys in source code)
- Insecure deserialization
- SSRF (server-side request forgery)

For each vulnerability, trace the data flow from user input to the dangerous sink to confirm it's exploitable.

Return ONLY a JSON array. Each finding must have these exact keys:
- "file": relative file path
- "line": line number (approximate)
- "function": function name containing the vulnerability
- "type": one of "sql_injection", "command_injection", "xss", "path_traversal", "hardcoded_credentials", "ssrf"
- "severity": "critical", "high", or "medium"
- "description": brief explanation of the vulnerability and how it could be exploited
- "code_snippet": the vulnerable lines of code (include the function signature and the vulnerable line)

Return ONLY the JSON array, no other text, no markdown fences."""


def _collect_source_files(target_path: str, max_files: int = 20, max_total_chars: int = 30000) -> tuple[str, dict]:
    """Collect all Python source files from the target directory into a single listing.

    Returns (listing, info) where info reports truncation so callers can warn
    that large repos may be under-scanned.
    """
    chunks = []
    total_chars = 0
    file_count = 0
    truncated = False
    collected_relpaths: list[str] = []

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in (
            "__pycache__", ".git", ".venv", "venv", "node_modules",
            "env", ".env", "dist", "build", ".tox",
        )]

        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            if file_count >= max_files or total_chars >= max_total_chars:
                truncated = True
                break

            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, target_path)

            try:
                with open(fpath) as f:
                    code = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            remaining = max_total_chars - total_chars
            if len(code) > remaining:
                code = code[:remaining] + "\n# ... (truncated)"
                truncated = True

            chunks.append(f"{'='*60}\n# FILE: {relpath}\n{'='*60}\n{code}\n")
            collected_relpaths.append(relpath)
            total_chars += len(code) + 100
            file_count += 1

        if truncated:
            break

    info = {
        "truncated": truncated,
        "files": file_count,
        "chars": total_chars,
        "relpaths": collected_relpaths,
    }
    return "\n".join(chunks), info


REQUIRED_FINDING_KEYS = ("file", "function", "type")
KNOWN_TYPES = {
    "sql_injection", "command_injection", "xss", "path_traversal",
    "hardcoded_credentials", "ssrf",
}
KNOWN_SEVERITIES = {"critical", "high", "medium"}


def _normalize_finding(raw: object, target_path: str) -> tuple[dict | None, str]:
    """Validate one recon finding. Returns (finding, reject_reason)."""
    if not isinstance(raw, dict):
        return None, "finding is not a JSON object"
    for key in REQUIRED_FINDING_KEYS:
        if not raw.get(key):
            return None, f"finding is missing required key '{key}'"

    relpath = str(raw["file"]).replace("\\", "/").strip()
    # Findings must stay inside the target tree: no absolute paths, no escape.
    if os.path.isabs(relpath) or relpath.startswith("~"):
        return None, f"file escapes target (absolute path): {relpath[:80]}"
    normed = os.path.normpath(relpath).replace("\\", "/")
    if normed.startswith("..") or normed == ".":
        return None, f"file escapes target (..): {relpath[:80]}"
    if not normed.endswith(".py"):
        return None, f"file is not a Python module: {relpath[:80]}"

    try:
        line = int(raw.get("line", 0))
    except (TypeError, ValueError):
        line = 0

    severity = str(raw.get("severity", "medium")).lower()
    if severity not in KNOWN_SEVERITIES:
        severity = "medium"

    finding = {
        "target_path": target_path,
        "file": normed,
        "line": max(line, 0),
        "function": str(raw["function"]),
        "type": str(raw["type"]),
        "severity": severity,
        "description": str(raw.get("description", "")),
        "code_snippet": str(raw.get("code_snippet", "")),
    }
    return finding, ""


def _missing_dependencies(target_path: str, relpaths: list[str]) -> list[str]:
    """Pre-flight: which third-party modules do target files import that are
    NOT installed here? Exploit scripts importing them cannot run, so those
    findings would be UNVERIFIED — warn upfront instead of failing silently.

    Pure AST analysis: no target code is executed.
    """
    local_tops = set()
    for rel in relpaths:
        parts = rel.split("/")
        local_tops.add(parts[0][:-3] if parts[0].endswith(".py") else parts[0])
        if len(parts) > 1:
            local_tops.add(parts[0])

    needed: set[str] = set()
    for rel in relpaths:
        try:
            with open(os.path.join(target_path, rel)) as f:
                tree = ast.parse(f.read())
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    needed.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import: local by definition
                if node.module:
                    needed.add(node.module.split(".")[0])

    missing = []
    old_path = list(sys.path)
    sys.path.insert(0, target_path)
    try:
        for name in sorted(needed - local_tops):
            try:
                if importlib.util.find_spec(name) is None:
                    missing.append(name)
            except (ImportError, ValueError, AttributeError):
                missing.append(name)
    finally:
        sys.path[:] = old_path
    return missing


async def recon_scan(target_path: str, client=None) -> tuple[list[dict], list[str]]:
    """Scan the target. Returns (findings, warnings)."""
    if client is None:
        client = get_client()

    code_listing, info = _collect_source_files(target_path)

    warnings: list[str] = []
    if info["truncated"]:
        warnings.append(
            f"[Recon] Source truncated to {info['files']} files "
            f"({info['chars']} chars) — large repos may be under-scanned."
        )

    if not code_listing:
        return [], warnings

    missing = _missing_dependencies(target_path, info["relpaths"])
    if missing:
        warnings.append(
            f"[Recon] Modules imported by target but not installed here: "
            f"{', '.join(missing)}. Exploit scripts needing them will be "
            f"UNVERIFIED, not confirmed."
        )

    user_msg = f"""Project root: {target_path}

Below is the complete source code of the project. Analyze ALL files for security vulnerabilities:

{code_listing}

Return a JSON array of all vulnerabilities found."""

    try:
        response = await client.generate(
            system_prompt=RECON_SYSTEM,
            user_message=user_msg,
            max_tokens=4096,
            temperature=0.1,
        )
        response = response.strip()

        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
            response = response.strip()

        raw_findings = json.loads(response)
        if isinstance(raw_findings, dict):
            # Some models wrap the array: {"vulnerabilities": [...]}
            for key in ("vulnerabilities", "findings", "results"):
                if isinstance(raw_findings.get(key), list):
                    raw_findings = raw_findings[key]
                    break
        if not isinstance(raw_findings, list):
            warnings.append("[Recon] Model did not return a finding list — treating as no findings.")
            return [], warnings

        findings = []
        rejected = 0
        for raw in raw_findings:
            finding, reason = _normalize_finding(raw, target_path)
            if finding is None:
                rejected += 1
                print(f"[recon] Rejected malformed finding: {reason}", file=sys.stderr)
                continue
            if finding["type"] not in KNOWN_TYPES:
                warnings.append(
                    f"[Recon] Unknown vulnerability type '{finding['type']}' "
                    f"in {finding['function']} — kept, verify carefully."
                )
            findings.append(finding)

        if rejected:
            warnings.append(f"[Recon] Rejected {rejected} malformed finding(s) (see stderr).")

        return findings, warnings

    except json.JSONDecodeError as e:
        import sys
        print(f"[recon] JSON parse error: {e}", file=sys.stderr)
        print(f"[recon] Raw response: {response[:500]}", file=sys.stderr)
        warnings.append("[Recon] Could not parse model output — no findings this run.")
        return [], warnings
    except Exception as e:
        import sys
        print(f"[recon] Error: {e}", file=sys.stderr)
        warnings.append(f"[Recon] Scan failed ({e}) — no findings this run.")
        return [], warnings
