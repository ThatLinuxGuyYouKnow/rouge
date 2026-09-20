import asyncio
import os
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.markdown import Markdown
from .graph import run_rouge
from . import config as rouge_config

console = Console()

BANNER = """
[red bold]▄▄▄  ▄▄▄  ▄▄▄ ▄▄▄  ▄▄▄ ▄▄▄[/red bold]
[red bold]█▄▄▀ █ █ █ █ █ █ █ █ █ █[/red bold]
[red bold]█    █▄█ █▄█ █ █ █▄▀ █▄▀[/red bold]
[red bold]      ROGUE[/red bold]
[dim]Autonomous AI Red Team & Remediation Hive[/dim]
"""


@click.group()
def main():
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--mode", "-m", type=click.Choice(["fix", "report"]), default="fix",
              help="fix: generate and validate a patch for the top vulnerability | report: write a full markdown report")
@click.option("--model", default=None,
              help="LiteLLM model string, e.g. openai/qwen-max, gpt-4o, claude-sonnet-4-5, ollama/llama3.1. Overrides config file and env.")
@click.option("--api-key", default=None, help="API key for the model provider. Overrides ROUGE_API_KEY and config file.")
@click.option("--api-base", default=None, help="Custom base URL for OpenAI-compatible endpoints. Overrides ROUGE_API_BASE and config file.")
def scan(target: str, mode: str, model: str | None, api_key: str | None, api_base: str | None):
    """Full autonomous scan: find, validate, and prioritize vulnerabilities."""
    if model:
        os.environ["ROUGE_MODEL"] = model
    if api_key:
        os.environ["ROUGE_API_KEY"] = api_key
    if api_base:
        os.environ["ROUGE_API_BASE"] = api_base
    rouge_config.new_session_id()

    console.print(BANNER)
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Model:[/bold] {rouge_config.current_model()}\n")

    state = asyncio.run(run_rouge(target, mode=mode))

    for msg in state.get("log", []):
        console.print(f"  {msg}")

    console.print("")

    if state.get("findings"):
        table = Table(title="Scan Results", show_header=True, header_style="bold")
        table.add_column("Status", style="bold")
        table.add_column("Type")
        table.add_column("Location")
        table.add_column("Description")

        confirmed_set = {c.get("function", "") for c in state.get("confirmed", [])}
        inconclusive_reasons = {c.get("function", ""): c.get("verification_reason", "")
                                for c in state.get("inconclusive", [])}

        for f in state["findings"]:
            if f["function"] in confirmed_set:
                status = "[green]CONFIRMED[/green]"
            elif f["function"] in inconclusive_reasons:
                status = "[yellow]UNVERIFIED[/yellow]"
            else:
                status = "[dim]FALSE POSITIVE[/dim]"
            table.add_row(
                status,
                f["type"],
                f"{f['file']}:{f['line']} ({f['function']})",
                f.get("description", "")[:80],
            )

        console.print(table)

    if not state.get("confirmed") and not state.get("inconclusive"):
        console.print(Panel.fit(
            "[bold green]VERT — Clean Bill of Health[/bold green]\n"
            "No exploitable vulnerabilities were confirmed.",
            title="Status",
        ))
    elif not state.get("confirmed"):
        console.print(Panel.fit(
            f"[bold yellow]INCOMPLETE — not a clean bill of health[/bold yellow]\n"
            f"{len(state['inconclusive'])} finding(s) could not be verified "
            f"(see UNVERIFIED rows). Re-run with target dependencies installed "
            f"or review them manually.",
            title="Status",
        ))

    if state.get("top_vuln"):
        top = state["top_vuln"]
        console.print(Panel.fit(
            f"[bold red]Top Priority: {top['type']}[/bold red]\n"
            f"Function: {top['function']} in {top['file']}:{top['line']}\n"
            f"{top.get('description', '')}",
            title="Priority Finding"
        ))

    if state.get("patch_result"):
        pr = state["patch_result"]
        console.print(Panel.fit(
            f"[bold green]Patch Generated & Verified[/bold green]\n"
            f"Attempts: {pr['attempts']}\n"
            f"Changes: {pr['changes_summary']}\n\n"
            f"[bold]Fixed function:[/bold]\n{pr['patched_function']}",
            title="Patch"
        ))

    if state.get("report_path"):
        console.print(Panel.fit(
            f"[bold green]Report Saved[/bold green]\n"
            f"{state['report_path']}\n\n"
            f"Copy the contents to share with another agent or LLM.",
            title="Report"
        ))

    if state.get("log_path"):
        console.print(Panel.fit(
            f"[bold cyan]Agent Log Saved[/bold cyan]\n"
            f"{state['log_path']}",
            title="Log"
        ))


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.argument("function_name")
@click.argument("vuln_type")
@click.option("--model", default=None, help="LiteLLM model string. Overrides config file and env.")
@click.option("--api-key", default=None, help="API key for the model provider.")
@click.option("--api-base", default=None, help="Custom base URL for OpenAI-compatible endpoints.")
def fix(target: str, function_name: str, vuln_type: str, model: str | None, api_key: str | None, api_base: str | None):
    """Generate a patch for a specific vulnerability."""
    from .agents.patch import generate_and_validate_patch
    from .client import get_client
    import os

    console.print(BANNER)
    console.print(f"[bold]Fixing:[/bold] {function_name} ({vuln_type}) in {target}\n")

    finding = {
        "target_path": os.path.abspath(target),
        "file": f"{function_name}.py",
        "function": function_name,
        "type": vuln_type,
        "line": 1,
        "description": f"{vuln_type} in {function_name}",
        "code_snippet": "",
    }

    client = get_client(model=model, api_key=api_key, api_base=api_base)
    result = asyncio.run(generate_and_validate_patch(finding, client))

    if result:
        console.print("[bold green]Patch generated and verified:[/bold green]")
        console.print(f"  {result['changes_summary']}")
        console.print(f"  Attempts: {result['attempts']}")
        console.print(f"\n[bold]Patched function:[/bold]")
        console.print(Syntax(result["patched_function"], "python"))
    else:
        console.print("[red]Failed to generate a validated patch.[/red]")


@main.command()
@click.option("--provider", "-p", default=None,
              help="Provider preset to configure non-interactively: qwen, openai, anthropic, gemini, groq, openrouter, ollama, opencode, custom.")
@click.option("--model", default=None, help="LiteLLM model string (non-interactive mode).")
@click.option("--api-key", default=None, help="API key (non-interactive mode).")
@click.option("--api-base", default=None, help="Custom base URL (non-interactive mode).")
@click.option("--skip-check", is_flag=True, help="Skip the live validation call and save anyway.")
@click.option("--show", "show_only", is_flag=True, help="Show the current configuration and exit.")
@click.option("--reset", is_flag=True, help="Delete the saved configuration and exit.")
def setup(provider: str | None, model: str | None, api_key: str | None,
           api_base: str | None, skip_check: bool, show_only: bool, reset: bool):
    """Configure the LLM provider: pick a model, enter an API key, validate, save.

    Interactive wizard when run bare (`rouge setup`). Saves to ~/.rouge/config.json.
    """
    from .config import PROVIDERS, load_config, save_config, clear_config, redact, config_path

    console.print(BANNER)

    if reset:
        if clear_config():
            console.print("[green]Saved configuration deleted.[/green]")
        else:
            console.print("[dim]No saved configuration found.[/dim]")
        return

    saved = load_config()

    if show_only:
        _show_config(saved)
        return

    # --- Non-interactive mode: --provider and/or --model given ---
    if provider or model:
        if provider and provider not in PROVIDERS:
            console.print(f"[red]Unknown provider '{provider}'. Choose from: {', '.join(PROVIDERS)}[/red]")
            raise SystemExit(1)
        preset = PROVIDERS.get(provider or "", {})
        final_model = model or preset.get("model", "")
        final_base = api_base if api_base is not None else preset.get("api_base", "")
        final_key = api_key or ""
        if not final_model:
            console.print("[red]No model given. Use --model '<litellm model string>'.[/red]")
            raise SystemExit(1)
        if preset.get("needs_key") and not final_key and not os.environ.get(preset.get("key_env", "")):
            console.print(f"[red]This provider needs an API key. Pass --api-key or set {preset.get('key_env')}.[/red]")
            raise SystemExit(1)
        _validate_and_save(final_model, final_key, final_base, skip_check=skip_check)
        return

    # --- Interactive wizard ---
    _show_config(saved)

    names = list(PROVIDERS.keys())
    console.print("[bold]Choose a provider:[/bold]")
    for i, name in enumerate(names, 1):
        preset = PROVIDERS[name]
        marker = " [dim](current)[/dim]" if saved.get("model") and _preset_matches(saved, name, preset) else ""
        console.print(f"  [cyan]{i}[/cyan]. {preset['label']}{marker}")
    console.print("")

    choice = click.prompt("Provider", type=click.IntRange(1, len(names)), default=1)
    pname = names[choice - 1]
    preset = PROVIDERS[pname]

    default_model = saved.get("model") if saved.get("model") and _preset_matches(saved, pname, preset) else preset["model"]
    if pname == "custom":
        final_model = click.prompt("Model (LiteLLM format, e.g. openai/qwen-max, gpt-4o, ollama/llama3.1)",
                                   default=default_model or "")
        while not final_model.strip():
            console.print("[red]Model is required.[/red]")
            final_model = click.prompt("Model", default="")
        final_model = final_model.strip()
    else:
        final_model = click.prompt("Model", default=default_model).strip() or default_model

    final_key = ""
    if preset.get("needs_key"):
        key_env = preset.get("key_env", "")
        env_has_key = bool(os.environ.get(key_env, ""))
        existing = saved.get("api_key", "")
        if existing:
            keep = click.prompt(f"API key is set ({rouge_config.redact(existing)}). Press Enter to keep, or paste a new one",
                                default="", hide_input=True, show_default=False)
            final_key = existing if not keep else keep.strip()
        else:
            hint = f" (or set {key_env}{', found in env ✓' if env_has_key else ''})"
            final_key = click.prompt(f"API key{hint}", default="", hide_input=True, show_default=False).strip()
            if not final_key and key_env:
                console.print(f"  [dim]Get one at {preset.get('key_url')}[/dim]")
    elif pname == "custom":
        final_key = click.prompt("API key (Enter to skip — not needed for local endpoints)",
                                 default="", hide_input=True, show_default=False).strip()

    default_base = saved.get("api_base", "") if saved.get("model") == final_model else preset.get("api_base", "")
    if pname in ("qwen", "custom", "ollama") or default_base:
        final_base = click.prompt("Base URL (Enter to keep default)", default=default_base).strip()
    else:
        final_base = ""

    _validate_and_save(final_model, final_key, final_base, skip_check=False, interactive=True)


def _preset_matches(saved: dict, pname: str, preset: dict) -> bool:
    """Heuristic: does the saved model look like it came from this preset?"""
    m = saved.get("model", "")
    if pname == "qwen":
        return "qwen" in m
    if pname == "custom":
        return True
    key = pname.split("/")[0]
    return m == preset.get("model") or m.startswith(key + "/") or m.startswith(key + "-")


def _show_config(saved: dict) -> None:
    from .config import redact
    if saved.get("model"):
        console.print(Panel.fit(
            f"[bold]Model:[/bold] {saved['model']}\n"
            f"[bold]API key:[/bold] {redact(saved.get('api_key', ''))}\n"
            f"[bold]Base URL:[/bold] {saved.get('api_base') or '(provider default)'}\n"
            f"[dim]From: {rouge_config.config_path()}[/dim]",
            title="Current configuration",
        ))
    else:
        console.print("[dim]No saved configuration yet. Let's set one up.[/dim]")
    env_model = os.environ.get("ROUGE_MODEL")
    if env_model:
        console.print(f"[yellow]Note: ROUGE_MODEL={env_model} in env will override the saved config.[/yellow]")
    console.print("")


def _validate_and_save(model: str, api_key: str, api_base: str,
                       skip_check: bool = False, interactive: bool = False) -> None:
    """Run a tiny live call to validate the credentials, then save."""
    from .client import get_client

    if not skip_check:
        console.print(f"\n[dim]Validating {model} with a test call...[/dim]")
        try:
            client = get_client(model=model, api_key=api_key or None, api_base=api_base or None)
            reply = asyncio.run(client.generate(
                system_prompt="You are a connectivity test.",
                user_message="Reply with exactly: OK",
                max_tokens=10,
                temperature=0,
            ))
            console.print(f"[green]✓ Provider responded:[/green] [dim]{reply.strip()[:100]}[/dim]")
        except Exception as e:
            console.print(f"[red]✗ Validation failed:[/red] {e}\n")
            if interactive:
                action = click.prompt("What next? [r]etry setup / [s]ave anyway / [a]bort",
                                      type=click.Choice(["r", "s", "a"]), default="r")
                if action == "r":
                    console.print("[dim]Re-run `rouge setup` to try again.[/dim]")
                    return
                if action == "a":
                    console.print("[dim]Nothing saved.[/dim]")
                    return
            else:
                console.print("[dim]Hint: re-run without --skip-check after fixing the key/model, "
                              "or add --skip-check to save anyway.[/dim]")
                raise SystemExit(1)

    path = rouge_config.save_config(model, api_key, api_base)
    console.print(Panel.fit(
        f"[bold green]Configuration saved[/bold green]\n"
        f"Model: {model}\n"
        f"Key: {rouge_config.redact(api_key)}\n"
        f"Base URL: {api_base or '(provider default)'}\n"
        f"[dim]{path} (mode 0600)[/dim]\n\n"
        f"Run [bold]rouge scan <path>[/bold] to start. "
        f"Override anytime with --model/--api-key/--api-base or ROUGE_* env vars.",
        title="Setup complete",
    ))


@main.command()
@click.option("--port", "-p", type=int, default=8765, help="Port for the monitoring station web server.")
@click.option("--open", "open_browser", is_flag=True, help="Open the dashboard in a browser on startup.")
def monitor(port: int, open_browser: bool):
    """Start the monitoring station web dashboard (live agent logs)."""
    from .monitor import serve

    console.print(BANNER)
    console.print(f"[bold]Monitoring Station[/bold]")
    console.print(f"  Dashboard: [cyan]http://localhost:{port}[/cyan]")
    console.print(f"  Trigger scans and watch agent logs stream in real time.\n")

    if open_browser:
        import webbrowser, threading
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{port}")).start()

    serve(port=port)


if __name__ == "__main__":
    main()
