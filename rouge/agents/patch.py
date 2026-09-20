import ast
import json
import os
import re
import shutil
import sys
import tempfile
from ..client import get_client
from .sandbox import (
    check_script,
    run_script,
    script_exercises_target,
    scrub_env,
    snapshot_tree,
    PATCH_OK_MARKER,
    PATCH_FAIL_MARKER,
)

PATCH_SYSTEM = """You are a secure code developer (The Sentinel Agent). Your job is to fix confirmed vulnerabilities in source code by generating minimal, secure patches.

Given:
1. The vulnerability details (type, file, line, function)
2. The original source code of the file
3. The exploit that proves the vulnerability

Generate the corrected version of the ENTIRE vulnerable function. The fix must:
- Use parameterized queries for SQL injection fixes (e.g., cursor.execute("SELECT ... WHERE col = ?", (value,)))
- Use subprocess.run with shell=False and argument lists for command injection
- Use html.escape() for XSS
- Sanitize file paths with os.path.basename or os.path.realpath + boundary check for path traversal
- Remove hardcoded credentials and use environment variables instead
- Be minimal - only change what's necessary to fix the vulnerability

Return a JSON object with:
{
  "fixed_function": "<the complete corrected function code including the def line>",
  "changes_summary": "<brief description of what was changed and why>",
  "imports_needed": ["<any new imports needed, e.g. 'html', 'subprocess'>"]
}

Return ONLY the JSON object, no other text, no markdown fences."""

VALIDATE_SYSTEM = """You are a security test engineer. You need to write a Python test script that verifies a security patch works.

The test script should:
1. Import the PATCHED function from the given module
2. Try the SAME exploit payload that previously worked
3. Print "PATCH_VERIFIED: <reason>" and exit with code 0 if the exploit is NOW BLOCKED (patch successful)
4. Print "PATCH_FAILED: <reason>" and exit with code 1 if the exploit STILL WORKS (patch failed)

The test harness enforces this contract strictly: exiting 0 WITHOUT printing
"PATCH_VERIFIED:" counts as INCONCLUSIVE (patch not accepted), and the script
must reference the patched module and function.

Rules:
- Use `from MODULE import FUNCTION` (the isolated directory is already on sys.path)
- Do NOT make network calls, use subprocess, write files, or modify the system
- Do NOT use `os.system`, `eval`, `exec`, `open(..., "w")`, or `input()`
- Keep it under 50 lines

Return ONLY the Python script. Wrap in ```python ... ```"""

MAX_PATCH_RETRIES = 3


async def generate_and_validate_patch(
    vuln: dict,
    client=None,
) -> dict | None:
    if client is None:
        client = get_client()

    target_path = vuln.get("target_path", ".")
    file_relpath = vuln["file"]
    file_path = os.path.join(target_path, file_relpath)
    module_name = os.path.splitext(file_relpath)[0].replace("/", ".").replace("\\", ".")

    with open(file_path) as f:
        full_source = f.read()

    for attempt in range(MAX_PATCH_RETRIES):
        user_msg = f"""Vulnerability type: {vuln["type"]}
File: {file_relpath}
Function: {vuln["function"]}
Line: {vuln["line"]}
Description: {vuln["description"]}

Original source code of {file_relpath}:
```python
{full_source}
```

The exploit that proved this vulnerability:
```python
{vuln.get("exploit_code", "N/A")}
```

Exploit output: {vuln.get("exploit_output", "N/A")}

Generate the corrected function code."""

        try:
            response = await client.generate(
                system_prompt=PATCH_SYSTEM,
                user_message=user_msg,
                max_tokens=2048,
                temperature=0.1,
            )
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
                response = response.strip()

            patch_data = json.loads(response)
        except (json.JSONDecodeError, Exception) as e:
            import sys
            print(f"[patch] Attempt {attempt+1}: JSON parse error: {e}", file=sys.stderr)
            if attempt < MAX_PATCH_RETRIES - 1:
                continue
            return None

        fixed_func = patch_data.get("fixed_function", "")
        imports_needed = patch_data.get("imports_needed", [])
        changes = patch_data.get("changes_summary", "")

        if not fixed_func:
            continue

        patched_source = _apply_patch_to_source(
            full_source, vuln["function"], fixed_func, imports_needed,
            near_line=vuln.get("line", 0),
        )

        # Validate against a full-tree overlay: copy the target so sibling
        # modules, packages and relative imports resolve, then overwrite the
        # single patched file. Nested modules (pkg/mod.py) import correctly.
        tmpdir = tempfile.mkdtemp(prefix="rouge_patch_")
        try:
            workdir = snapshot_tree(target_path)
        except Exception as e:
            print(f"[patch] Isolation copy failed ({e}); validating in place.", file=sys.stderr)
            workdir = None
        if workdir is None:
            overlay = tmpdir
            patched_file = os.path.join(overlay, os.path.basename(file_relpath))
            snapshot_root = None
        else:
            overlay = workdir
            patched_file = os.path.join(overlay, file_relpath)
            os.makedirs(os.path.dirname(patched_file) or overlay, exist_ok=True)
            snapshot_root = os.path.dirname(workdir)

        def _cleanup() -> None:
            shutil.rmtree(tmpdir, ignore_errors=True)
            if snapshot_root:
                shutil.rmtree(snapshot_root, ignore_errors=True)

        with open(patched_file, "w") as f:
            f.write(patched_source)

        validate_msg = f"""Isolated test directory: {overlay}
Module to import: {module_name}
Vulnerability type: {vuln["type"]}
Function: {vuln["function"]}

The patched source code is:
```python
{patched_source}
```

Write a Python test script that verifies the patch blocks the original exploit."""

        try:
            validate_response = await client.generate(
                system_prompt=VALIDATE_SYSTEM,
                user_message=validate_msg,
                max_tokens=2048,
                temperature=0.2,
            )
            validate_code = _extract_code(validate_response)
        except Exception:
            _cleanup()
            continue

        if not validate_code:
            _cleanup()
            continue

        # Gate the validation script like exploit scripts: it must be safe
        # and must actually exercise the patched target.
        ok, reason = check_script(validate_code)
        if ok and not script_exercises_target(validate_code, module_name, vuln["function"]):
            ok, reason = False, "validation script does not reference the patched target"
        if not ok:
            print(f"[patch] Attempt {attempt+1}: rejected validation script ({reason})", file=sys.stderr)
            _cleanup()
            continue

        validate_script = os.path.join(tmpdir, "test_patch.py")
        with open(validate_script, "w") as f:
            f.write(validate_code)

        exit_code, validation_output, status = run_script(validate_script, overlay, timeout=10)

        if status == "ok" and exit_code == 0 and PATCH_OK_MARKER in validation_output:
            _cleanup()
            return {
                "vulnerability": vuln,
                "patched_function": fixed_func,
                "imports_needed": imports_needed,
                "changes_summary": changes,
                "validation_output": validation_output,
                "attempts": attempt + 1,
            }

        if status == "ok":
            print(f"[patch] Attempt {attempt+1}: validation failed "
                  f"(exit={exit_code}, marker_present={PATCH_OK_MARKER in validation_output})",
                  file=sys.stderr)
        else:
            print(f"[patch] Attempt {attempt+1}: validation {status} ({validation_output[:150]})",
                  file=sys.stderr)
        _cleanup()

    return None


def _find_function_span(source: str, func_name: str, near_line: int) -> tuple[int, int] | None:
    """Locate (start, end) 0-based line span of `func_name` in source.

    Uses the AST so matches in comments/strings and same-named functions in
    other scopes don't collide. When several definitions share the name
    (methods in different classes, nested functions), the one closest to the
    reported `near_line` wins. Returns None if parsing fails or no match.
    Returns (span_start, def_line, end): span_start is the first decorator
    line (or the def line when undecorated) so the caller can decide whether
    original decorators survive the replacement.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    candidates = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            def_line = node.lineno - 1
            start = def_line
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list) - 1
            end = (node.end_lineno or node.lineno)  # end_lineno is 1-based inclusive
            candidates.append((start, def_line, end))

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if near_line and near_line > 0:
        return min(candidates, key=lambda span: abs(span[1] + 1 - near_line))
    return candidates[0]


def _anchored_fallback_span(lines: list[str], func_name: str) -> tuple[int, int] | None:
    """Fallback when the file doesn't parse: match `def name(` anchored at a
    line start (never inside comments/strings mid-line), first hit wins."""
    pattern = re.compile(rf"^[ \t]*def {re.escape(func_name)}\(")
    func_start = None
    indent_level = 0
    for i, line in enumerate(lines):
        if func_start is None and pattern.match(line):
            func_start = i
            indent_level = len(line) - len(line.lstrip())
            continue
        if func_start is not None and i > func_start:
            if line.strip() == "":
                continue
            if line.strip() and len(line) - len(line.lstrip()) <= indent_level:
                return func_start, i
    if func_start is not None:
        return func_start, len(lines)
    return None


def _insertion_point(lines: list[str]) -> int:
    """Where new imports go: after shebang/comments/blank lines, the module
    docstring, and existing imports — never before the docstring."""
    i, n = 0, len(lines)
    if i < n and lines[i].startswith("#!"):
        i += 1
    while i < n and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    # Skip a module docstring (single- or multi-line).
    if i < n:
        stripped = lines[i].lstrip()
        for quote in ('"""', "'''"):
            if stripped.startswith(quote):
                if stripped.count(quote) >= 2 and len(stripped) > len(quote):
                    i += 1
                else:
                    i += 1
                    while i < n and quote not in lines[i]:
                        i += 1
                    i += 1  # closing line
                break
    while i < n:
        s = lines[i].strip()
        if not s or s.startswith("#"):
            i += 1
        elif s.startswith("import ") or s.startswith("from "):
            i += 1
        else:
            break
    return i


def _apply_patch_to_source(
    source: str, func_name: str, fixed_func: str, imports: list[str], near_line: int = 0
) -> str:
    lines = source.split("\n")

    new_imports = []
    for imp in imports:
        imp = imp.strip()
        if not imp or imp in source:
            continue
        if "." in imp and not imp.startswith("from "):
            parts = imp.rsplit(".", 1)
            new_imports.append(f"from {parts[0]} import {parts[1]}")
        elif "." in imp:
            new_imports.append(imp)
        else:
            new_imports.append(f"import {imp}")

    span = _find_function_span(source, func_name, near_line)
    if span is None:
        fallback = _anchored_fallback_span(lines, func_name)
        span = (fallback[0], fallback[0], fallback[1]) if fallback else None

    if span is not None:
        func_start, def_line, func_end = span
        # If the original is decorated but the fix brings no decorators of
        # its own, keep the originals (e.g. @app.get routes) and replace
        # only from the def line. If the fix re-states decorators, it wins.
        fixed_first = next((l for l in fixed_func.strip().split("\n") if l.strip()), "")
        if func_start < def_line and not fixed_first.lstrip().startswith("@"):
            func_start = def_line
        try:
            indent_level = len(lines[func_start]) - len(lines[func_start].lstrip())
        except IndexError:
            indent_level = 0
        fixed_lines = fixed_func.strip().split("\n")
        indented_fix = []
        for i, fline in enumerate(fixed_lines):
            if fline.strip() == "":
                indented_fix.append("")
            elif i == 0:
                indented_fix.append(" " * indent_level + fline.strip())
            else:
                stripped = fline.lstrip()
                relative_indent = len(fline) - len(stripped)
                indented_fix.append(" " * (indent_level + relative_indent) + stripped)

        new_lines = lines[:func_start] + indented_fix + [""] + lines[func_end:]

        if new_imports:
            insert_at = _insertion_point(new_lines)
            for imp in reversed(new_imports):
                new_lines.insert(insert_at, imp)

        return "\n".join(new_lines)

    return source


def _extract_code(response: str) -> str:
    response = (response or "").strip()
    if "```python" in response:
        parts = response.split("```python", 1)
        if len(parts) > 1:
            return parts[1].split("```")[0].strip()
        return ""
    if "```" in response:
        parts = response.split("```")
        if len(parts) > 1:
            return parts[1].strip()
    return response
