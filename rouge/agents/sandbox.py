"""Safety harness for executing LLM-generated test scripts.

The scripts rouge runs are written by an LLM that has just read *untrusted*
third-party code (the scan target), which may contain prompt-injection payloads.
This module is a guardrail layer — static checks, secret scrubbing, filesystem
isolation, output caps — not a security boundary. True isolation (containers,
seccomp, user namespaces) is future work and should be assumed necessary
before pointing rouge at actively hostile code.
"""

import ast
import os
import shutil
import subprocess
import sys
import tempfile

OUTPUT_CAP = 8000  # chars kept from a script's combined stdout+stderr

VULN_MARKER = "VULNERABLE:"
SAFE_MARKER = "NOT_VULNERABLE:"
PATCH_OK_MARKER = "PATCH_VERIFIED:"
PATCH_FAIL_MARKER = "PATCH_FAILED:"

# Network / process / IPC modules a *test* script never legitimately needs.
# (The script tests the target by calling its functions; the target module
# itself may use subprocess etc. — that is fine, only the script is gated.)
DENIED_MODULES = {
    "socket", "ssl", "requests", "urllib", "urllib3", "http", "httpx",
    "aiohttp", "ftplib", "smtplib", "telnetlib", "xmlrpc", "websocket",
    "websockets", "subprocess", "multiprocessing", "concurrent", "ctypes",
    "pty", "tty", "shutil", "signal",
}

# Dangerous builtins. exit()/sys.exit() are allowed (the protocol needs them).
DENIED_BUILTINS = {"eval", "exec", "compile", "__import__", "input"}

# Attribute calls denied on ANY receiver (no builtin str/list/dict/set type
# defines these, so this overwhelmingly targets os/shutil/pathlib usage).
DENIED_ATTRS_ANY = {
    "system", "popen", "execv", "execve", "execl", "execlp", "execvp",
    "spawnl", "spawnlp", "spawnv", "spawnvp",
    "write_text", "write_bytes", "unlink", "mkdir", "rmdir", "touch",
    "symlink_to", "hardlink_to", "chmod", "lchmod",
    "Popen", "check_output", "check_call",
}

# Extra attribute calls denied only when the receiver is recognisably an
# os-like module (str.replace() etc. must keep working for output checks).
_OS_RECEIVERS = {"os", "shutil", "path"}
DENIED_ATTRS_OS = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "renames",
    "mkdir", "makedirs", "chmod", "chown", "symlink", "link",
    "truncate", "kill",
}

SNAPSHOT_IGNORE = (
    "__pycache__", ".git", ".venv", "venv", "node_modules", "env",
    ".env", "dist", "build", ".tox", "*.pyc", "*.pyo", ".mypy_cache",
    ".pytest_cache",
    # Never copy our own previous snapshots back into a new one (e.g. when
    # the target directory itself contains temp dirs) — that recurses.
    "rouge_work_*", "rouge_patch_*", "rouge_exploit_*",
)


class _GateVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.problems: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in DENIED_MODULES:
                self.problems.append(f"import of denied module '{alias.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            if top in DENIED_MODULES:
                self.problems.append(f"import from denied module '{node.module}'")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in DENIED_BUILTINS:
                self.problems.append(f"use of denied builtin '{func.id}()'")
            elif func.id == "open":
                mode = self._literal_str_arg(node, 1, "mode")
                if mode is not None and mode not in ("r", "rb", "rU", "U"):
                    self.problems.append(f"open() with write mode '{mode}'")
                elif mode is None and len(node.args) > 1:
                    self.problems.append("open() with non-literal mode")
        elif isinstance(func, ast.Attribute):
            if func.attr in DENIED_ATTRS_ANY:
                self.problems.append(f"call to denied '...{func.attr}()'")
            elif (func.attr in DENIED_ATTRS_OS
                    and isinstance(func.value, ast.Name)
                    and func.value.id in _OS_RECEIVERS):
                self.problems.append(f"call to denied '{func.value.id}.{func.attr}()'")
        self.generic_visit(node)

    @staticmethod
    def _literal_str_arg(node: ast.Call, pos: int, kw: str) -> str | None | bool:
        """Return the literal string value, None if absent, False if non-literal."""
        for keyword in node.keywords:
            if keyword.arg == kw and isinstance(keyword.value, ast.Constant):
                return keyword.value.value if isinstance(keyword.value.value, str) else False
        if len(node.args) > pos:
            arg = node.args[pos]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
            return False
        return None


def check_script(code: str) -> tuple[bool, str]:
    """Static safety gate. Returns (ok, reason). Empty reason when ok."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"script has syntax error: {e}"
    visitor = _GateVisitor()
    visitor.visit(tree)
    if visitor.problems:
        return False, "script violates safety policy: " + "; ".join(visitor.problems[:3])
    return True, ""


def script_exercises_target(code: str, module_name: str, func_name: str) -> bool:
    """Heuristic: does the script actually import/call the reported target?

    Guards against vacuous scripts that exit 0 without touching the target.
    """
    top = module_name.split(".")[-1]
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
            imported.update(a.name.split(".")[-1] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
            imported.add(node.module.split(".")[-1])
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    module_ok = top in imported or module_name in code or top in code
    func_ok = func_name in called or func_name in imported or func_name in code
    return bool(module_ok and func_ok)


def scrub_env(extra: dict | None = None) -> dict:
    """Child-process env with secrets removed.

    The scripts under test must never see API keys that happen to be in the
    parent environment (they run code shaped by untrusted scan targets).
    """
    sensitive = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD",
                 "CREDENTIAL", "AUTH", "SESSION")
    env = {k: v for k, v in os.environ.items()
           if not any(s in k.upper() for s in sensitive)}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def snapshot_tree(target_path: str) -> str:
    """Copy the target source tree to a temp dir for isolated execution.

    Exploit scripts routinely create side effects (sqlite DBs, files,
    __pycache__) — those must land in a disposable copy, never the user's repo.
    Caller owns cleanup (shutil.rmtree).
    """
    tmpdir = tempfile.mkdtemp(prefix="rouge_work_")
    dest = os.path.join(tmpdir, "target")
    shutil.copytree(
        target_path, dest,
        ignore=shutil.ignore_patterns(*SNAPSHOT_IGNORE),
    )
    return dest


def run_script(script_path: str, workdir: str, timeout: int = 10) -> tuple[int | None, str, str]:
    """Run a script with a scrubbed env in an isolated cwd.

    Returns (exit_code, capped_output, status) where status is one of
    "ok", "timeout", "error". exit_code is None unless status == "ok".
    """
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workdir,
            env=scrub_env({"PYTHONPATH": workdir}),
            stdin=subprocess.DEVNULL,
        )
        output = result.stdout + result.stderr
        if len(output) > OUTPUT_CAP:
            output = output[:OUTPUT_CAP] + f"\n... (truncated, {len(output)} chars total)"
        return result.returncode, output, "ok"
    except subprocess.TimeoutExpired:
        return None, f"script timed out after {timeout}s", "timeout"
    except Exception as e:
        return None, f"harness error: {e}", "error"
