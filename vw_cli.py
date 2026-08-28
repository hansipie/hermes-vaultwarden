"""CLI handlers for ``hermes vaultwarden ...``.

Registered through ``PluginContext.register_cli_command()`` — the wizard
lives here so :meth:`vw_source.VaultwardenSource.fetch` can stay strictly
non-interactive.

Subcommands:
    setup    — configure interactive-session or unattended API-key authentication
    status   — show current config + binary version + session presence
    sync     — run a fetch right now and show what would be applied (dry-run friendly)
    reset-auth — log out the profile-isolated bw CLI state
    disable  — flip ``secrets.vaultwarden.enabled`` to False
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from agent.secret_sources import registry as secret_registry
from agent.secret_sources.base import is_valid_env_name, run_secret_cli
from hermes_cli.config import load_config, save_config
from hermes_constants import get_hermes_home
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from . import vw_source as vw
except ImportError:  # loaded outside the plugin package (tests, direct import)
    import vw_source as vw


# ---------------------------------------------------------------------------
# Argparse wiring — setup_fn passed to PluginContext.register_cli_command
# ---------------------------------------------------------------------------


def setup_parser(parser: argparse.ArgumentParser) -> None:
    """Attach the sub-subcommands to the ``hermes vaultwarden`` parser."""
    parser.set_defaults(func=lambda args: (parser.print_help(), 0)[1])
    sub = parser.add_subparsers(dest="vw_command")

    setup = sub.add_parser(
        "setup",
        help="Configure Vaultwarden authentication and select a vault item",
    )
    setup.add_argument(
        "--item-name",
        help="Vault item name to read secrets from (skips interactive prompt)",
    )
    setup.add_argument(
        "--binary-path",
        help="Exact standalone bw binary path (recommended for sandboxed desktops)",
    )
    setup.add_argument(
        "--auto-unlock",
        action="store_true",
        help="Use BW_CLIENTID/BW_CLIENTSECRET/BW_MASTER_PASSWORD at startup",
    )
    setup.add_argument("--item-id", help="Immutable vault item ID (preferred)")
    setup.add_argument(
        "--server-url",
        help=(
            "Vaultwarden / Bitwarden server URL (e.g. https://vw.example.com). "
            "Interactive mode verifies the existing bw configuration; "
            "auto-unlock configures its isolated profile when needed.  "
            "Skip to keep the current bw server configuration."
        ),
    )
    setup.add_argument(
        "--username-env",
        help="Export the item's login.username under this env-var name (optional)",
    )
    setup.add_argument(
        "--password-env",
        help="Export the item's login.password under this env-var name (optional)",
    )
    setup.add_argument(
        "--notes-env",
        help="Export the item's notes under this env-var name (optional)",
    )
    setup.set_defaults(func=cmd_setup)

    status = sub.add_parser("status", help="Show config + binary + session status")
    status.set_defaults(func=cmd_status)

    sync = sub.add_parser("sync", help="Fetch secrets now and report what changed")
    sync.add_argument(
        "--apply",
        action="store_true",
        help="Export the secrets into the current process env (default: dry-run)",
    )
    sync.set_defaults(func=cmd_sync)

    reset_auth = sub.add_parser(
        "reset-auth", help="Log out this Hermes profile's isolated bw state"
    )
    reset_auth.set_defaults(func=cmd_reset_auth)

    disable = sub.add_parser("disable", help="Turn off the Vaultwarden integration")
    disable.set_defaults(func=cmd_disable)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    secrets_cfg = (cfg.setdefault("secrets", {})
                     .setdefault("vaultwarden", {}))
    console.print(
        Panel.fit(
            "[bold]Vaultwarden / Bitwarden Password Manager setup[/bold]\n\n"
            "Prerequisites — install the [cyan]bw[/cyan] CLI (pick one):\n"
            "  npm (recommended):  [cyan]npm install -g @bitwarden/cli[/cyan]\n"
            "  Snap (Linux):       [cyan]sudo snap install bw[/cyan]\n"
            "  Native x64 binary:  https://bitwarden.com/help/cli/\n"
            "    → chmod +x bw && mv bw ~/.local/bin/\n"
            "    → ARM64 users: use npm instead of the native binary\n\n"
            "For interactive use, export a session from [cyan]bw unlock --raw[/cyan].\n"
            "For unattended use, provide a personal API key and master password as\n"
            "[cyan]BW_CLIENTID[/cyan], [cyan]BW_CLIENTSECRET[/cyan], and "
            "[cyan]BW_MASTER_PASSWORD[/cyan].\n\n"
            "Secrets are read from a vault item's [bold]custom fields[/bold].  "
            "Name each field after the env var it should set "
            "(e.g. [cyan]OPENROUTER_API_KEY[/cyan]).",
            border_style="cyan",
        )
    )

    # ------------------------------------------------------------------ binary
    console.print()
    console.print("[bold]Step 1[/bold]  Locate the bw CLI")
    requested_binary = str(args.binary_path or "").strip()
    configured_binary = str(secrets_cfg.get("binary_path") or "").strip()
    binary = vw.find_bw(requested_binary or configured_binary or None)
    if binary is None:
        console.print(
            "  [red]bw not found on PATH or in <hermes_home>/bin.[/red]\n\n"
            "  Install it (pick one):\n"
            "    npm (recommended):  [cyan]npm install -g @bitwarden/cli[/cyan]\n"
            "    Snap (Linux):       [cyan]sudo snap install bw[/cyan]\n"
            "    Native x64 binary:  https://bitwarden.com/help/cli/\n"
            "      → chmod +x bw && mv bw ~/.local/bin/\n"
            "      → ARM64 users: use npm instead of the native binary\n\n"
            "  Then re-run this wizard."
        )
        return 1
    version = _bw_version(binary)
    console.print(f"  [green]✓[/green] {binary}  ({version})")

    # -- non-interactive guard --
    if not sys.stdin.isatty():
        missing = []
        if not args.auto_unlock and not os.environ.get("BW_SESSION", "").strip():
            missing.append("BW_SESSION or --auto-unlock")
        if args.auto_unlock and not (args.server_url and args.server_url.strip()):
            missing.append("--server-url")
        if not ((args.item_id and args.item_id.strip()) or (args.item_name and args.item_name.strip())):
            missing.append("--item-id or --item-name")
        if missing:
            console.print(
                f"  [red]Non-interactive mode (no TTY) requires all setup flags.[/red]\n"
                f"  Missing: {', '.join(missing)}\n\n"
                "  Usage:\n"
                "    hermes vaultwarden setup --auto-unlock \\\n"
                "      --server-url https://vault.example.com \\\n"
                "      --item-id '<vault-item-id>'"
            )
            return 1

    # ------------------------------------------------------------------ server
    server_url = (args.server_url or "").strip().rstrip("/")
    if server_url and not args.auto_unlock:
        if not server_url.startswith("https://"):
            console.print("  [red]--server-url must use HTTPS.[/red]")
            return 1
        current_server = _bw_current_server(binary).rstrip("/")
        if current_server != server_url:
            configured = current_server or "(default or unavailable)"
            console.print(
                "  [red]The configured bw server does not match --server-url.[/red]\n"
                f"  Configured: [cyan]{configured}[/cyan]\n"
                f"  Requested:  [cyan]{server_url}[/cyan]\n\n"
                f"  Run [cyan]bw config server {server_url}[/cyan], then log in, "
                "unlock, and re-run setup."
            )
            return 1
        console.print(f"  [green]✓[/green] verified bw server: {current_server}")
    elif not server_url and not args.auto_unlock:
        current_server = _bw_current_server(binary)
        if current_server:
            console.print(
                f"\n  [dim]Current bw server: {current_server}[/dim]\n"
                "  To change: [cyan]bw config server <url>[/cyan]"
            )

    # ------------------------------------------------------------------ session
    console.print()
    console.print("[bold]Step 3[/bold]  Authenticate")
    session_env = secrets_cfg.get("session_env", "BW_SESSION")

    session = os.environ.get(session_env, "").strip()
    appdata_dir = None
    if args.auto_unlock:
        try:
            session = vw.mint_session(
                binary,
                home_path=get_hermes_home(),
                server_url=server_url,
            )
            appdata_dir = vw._profile_bw_appdata(get_hermes_home())
        except RuntimeError as exc:
            console.print(f"  [red]Unattended authentication failed: {exc}[/red]")
            return 1
        console.print("  [green]✓[/green] API-key login and in-memory unlock succeeded")
    elif session:
        console.print(f"  [green]✓[/green] using {session_env} from the process environment")
    else:
        console.print(
            f"  [red]{session_env} is not set.[/red] Export the output of "
            "[cyan]bw unlock --raw[/cyan], or re-run with [cyan]--auto-unlock[/cyan]."
        )
        return 1

    # ------------------------------------------------------------------ item
    console.print()
    console.print("[bold]Step 4[/bold]  Pick a vault item")

    item_id = (args.item_id or "").strip()
    if item_id:
        item_name = item_id
        console.print(f"  Using item ID: [cyan]{item_id}[/cyan]")
    elif args.item_name and args.item_name.strip():
        item_name = args.item_name.strip()
        console.print(f"  Using item: [cyan]{item_name}[/cyan]")
    else:
        items = _list_items(binary, session, console, appdata_dir=appdata_dir)
        if items is None:
            return 1
        if not items:
            console.print(
                "  [yellow]No items found in the vault (or the session has expired).[/yellow]\n"
                "  Unlock again with [cyan]bw unlock[/cyan] and re-run setup."
            )
            return 1

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Name")
        table.add_column("ID", style="dim")
        for i, item in enumerate(items, 1):
            table.add_row(str(i), item.get("name", "?"), item.get("id", "?"))
        console.print(table)

        while True:
            choice = console.input(f"  Select item [1-{len(items)}]: ").strip()
            if not choice:
                continue
            try:
                idx = int(choice)
            except ValueError:
                console.print("  [red]Enter a number.[/red]")
                continue
            if 1 <= idx <= len(items):
                item_id = items[idx - 1]["id"]
                item_name = item_id
                break
            console.print(f"  [red]Out of range — pick 1-{len(items)}.[/red]")

    # ------------------------------------------------------------------ login bindings
    console.print()
    console.print("[bold]Step 4b[/bold]  Optional: map login fields to env vars")
    console.print(
        "  Leave blank to skip.  These export the vault item's structural "
        "login.username / login.password / notes fields — custom fields "
        "remain the primary way to export secrets in bulk."
    )

    def _prompt_binding(
        flag_value: Optional[str], label: str, arg_name: str
    ) -> Optional[str]:
        if flag_value and flag_value.strip():
            candidate = flag_value.strip()
            if not is_valid_env_name(candidate):
                console.print(
                    f"  [yellow]--{arg_name} {candidate!r} is not a valid "
                    "env-var name — ignoring it.[/yellow]"
                )
                return None
            return candidate
        if not sys.stdin.isatty():
            return None
        while True:
            raw = console.input(f"  {label} env var (blank = skip): ").strip()
            if not raw:
                return None
            if is_valid_env_name(raw):
                return raw
            console.print(
                f"  [red]{raw!r} is not a valid env-var name — try again.[/red]"
            )

    username_env = _prompt_binding(
        args.username_env, "login.username ->", "username-env"
    )
    password_env = _prompt_binding(
        args.password_env, "login.password ->", "password-env"
    )
    notes_env = _prompt_binding(args.notes_env, "notes ->", "notes-env")

    # ------------------------------------------------------------------ test
    console.print()
    console.print("[bold]Step 5[/bold]  Test fetch")
    try:
        secrets, warnings = vw.fetch_vaultwarden_secrets(
            session=session,
            item_name=item_name,
            binary=binary,
            use_cache=False,
            username_env=username_env,
            password_env=password_env,
            notes_env=notes_env,
            appdata_dir=appdata_dir,
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"  [red]✗ Fetch failed: {exc}[/red]")
        return 1

    if not secrets:
        console.print(
            "  [yellow]Fetch succeeded but no usable custom fields found.[/yellow]\n"
            "  Add custom fields to the vault item — name each field after the "
            "env var it should set (e.g. OPENROUTER_API_KEY)."
        )
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Field name", style="cyan")
        table.add_column("Status")
        for key in sorted(secrets):
            if key == session_env:
                status = "[dim]bootstrap token — never overrides itself[/dim]"
            elif os.environ.get(key):
                status = "[yellow]already set in env[/yellow]"
            else:
                status = "[green]new[/green]"
            table.add_row(key, status)
        console.print(table)
    for w in warnings:
        console.print(f"  [yellow]warning:[/yellow] {w}")

    # ------------------------------------------------------------------ save
    secrets_cfg["enabled"] = True
    if item_id:
        secrets_cfg["item_id"] = item_id
        secrets_cfg.pop("item_name", None)
    else:
        secrets_cfg["item_name"] = item_name
    secrets_cfg["auto_unlock"] = bool(args.auto_unlock)
    if server_url:
        secrets_cfg["server_url"] = server_url
    secrets_cfg.setdefault("session_env", session_env)
    secrets_cfg.setdefault("cache_ttl_seconds", 0)
    secrets_cfg.setdefault("override_existing", False)
    if requested_binary:
        secrets_cfg["binary_path"] = str(binary)

    for key, value in (
        ("username_env", username_env),
        ("password_env", password_env),
        ("notes_env", notes_env),
    ):
        if value:
            secrets_cfg[key] = value
        else:
            secrets_cfg.pop(key, None)

    # User plugins are opt-in — make sure this one is allowed to load.
    plugins_cfg = cfg.setdefault("plugins", {})
    enabled_plugins = plugins_cfg.setdefault("enabled", [])
    if isinstance(enabled_plugins, list) and "vaultwarden" not in enabled_plugins:
        enabled_plugins.append("vaultwarden")
        console.print("  [green]✓[/green] added 'vaultwarden' to plugins.enabled")

    save_config(cfg)

    console.print()
    console.print(
        "[green]✓ Vaultwarden integration is enabled.[/green]  "
        "Secrets are pulled at the start of Hermes processes."
    )
    console.print(
        "  Status:  [cyan]hermes vaultwarden status[/cyan]\n"
        "  Refresh: [cyan]hermes vaultwarden sync[/cyan]\n"
        "  Disable: [cyan]hermes vaultwarden disable[/cyan]\n\n"
        "  Auto-unlock sessions are minted in memory for each Hermes process and "
        "are never written to config or .env."
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    vw_cfg = (cfg.get("secrets") or {}).get("vaultwarden") or {}

    enabled = bool(vw_cfg.get("enabled"))
    auto_unlock = bool(vw_cfg.get("auto_unlock"))
    session_env = vw_cfg.get("session_env", "BW_SESSION")
    item_name = vw_cfg.get("item_id") or vw_cfg.get("item_name", "")
    session_set = bool(os.environ.get(session_env))
    plugin_enabled = "vaultwarden" in (
        (cfg.get("plugins") or {}).get("enabled") or []
    )

    binary = vw.find_bw(vw_cfg.get("binary_path"))
    login_bindings, binding_warnings = vw.resolve_login_bindings(vw_cfg)

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("", style="bold")
    table.add_column("")
    table.add_row("Plugin enabled",   _yn(plugin_enabled))
    table.add_row("Source enabled",   _yn(enabled))
    table.add_row("Auth mode",        "API key + auto-unlock" if auto_unlock else "session env")
    table.add_row("session_env",      session_env)
    table.add_row("session",          "[green]present[/green]" if session_set else "[dim]not supplied[/dim]")
    table.add_row("item",             item_name or "[dim](unset)[/dim]")
    table.add_row("username_env",     login_bindings["username_env"] or "[dim](unset)[/dim]")
    table.add_row("password_env",     login_bindings["password_env"] or "[dim](unset)[/dim]")
    table.add_row("notes_env",        login_bindings["notes_env"] or "[dim](unset)[/dim]")
    table.add_row("Override existing", _yn(bool(vw_cfg.get("override_existing", False))))
    table.add_row("Cache TTL (s)",    str(vw_cfg.get("cache_ttl_seconds", 0)))

    if auto_unlock:
        for key, default in (
            ("client_id_env", "BW_CLIENTID"),
            ("client_secret_env", "BW_CLIENTSECRET"),
            ("master_password_env", "BW_MASTER_PASSWORD"),
        ):
            env_name = str(vw_cfg.get(key) or default)
            table.add_row(env_name, "[green]present[/green]" if os.environ.get(env_name) else "[red]missing[/red]")

    if binary:
        appdata_dir = vw._profile_bw_appdata(get_hermes_home()) if auto_unlock else None
        server = _bw_current_server(binary, appdata_dir=appdata_dir)
        table.add_row("bw binary",   f"{binary} ({_bw_version(binary)})")
        table.add_row("bw server",   server or "[dim]default (bitwarden.com)[/dim]")
    else:
        table.add_row("bw binary",   "[red]not found[/red]")

    console.print(Panel(table, title="Vaultwarden / Bitwarden PM", border_style="cyan"))
    for w in binding_warnings:
        console.print(f"  [yellow]warning:[/yellow] {w}")

    if not plugin_enabled:
        console.print(
            "\n  [yellow]Plugin not in plugins.enabled — it will not load.[/yellow]\n"
            "  Run [cyan]hermes vaultwarden setup[/cyan] or add it manually to "
            "config.yaml."
        )
    elif not enabled:
        console.print("\n  Run [cyan]hermes vaultwarden setup[/cyan] to enable.")
    elif not session_set and not auto_unlock:
        console.print(
            f"\n  [yellow]Enabled but {session_env} is not set — Hermes will skip "
            "Vaultwarden and warn on next startup.[/yellow]\n"
            "  Unlock: [cyan]export BW_SESSION=$(bw unlock --raw)[/cyan]"
        )
    elif not item_name:
        console.print("\n  [yellow]Enabled but no item_name configured.[/yellow]")
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    vw_cfg = (cfg.get("secrets") or {}).get("vaultwarden") or {}
    if not vw_cfg.get("enabled"):
        console.print(
            "[yellow]Vaultwarden integration is disabled.  Run "
            "`hermes vaultwarden setup` first.[/yellow]"
        )
        return 1

    session_env = vw_cfg.get("session_env", "BW_SESSION")

    item_name = vw_cfg.get("item_id") or vw_cfg.get("item_name", "")
    if not item_name:
        console.print("[red]No item_name configured.[/red]")
        return 1

    binary = vw.find_bw(vw_cfg.get("binary_path"))
    if binary is None:
        console.print("[red]bw binary not found.[/red]")
        return 1

    session = os.environ.get(session_env, "").strip()
    appdata_dir = None
    if not session and vw_cfg.get("auto_unlock"):
        try:
            session = vw.mint_session(
                binary,
                home_path=get_hermes_home(),
                client_id_env=str(vw_cfg.get("client_id_env") or "BW_CLIENTID"),
                client_secret_env=str(vw_cfg.get("client_secret_env") or "BW_CLIENTSECRET"),
                master_password_env=str(vw_cfg.get("master_password_env") or "BW_MASTER_PASSWORD"),
                server_url=str(vw_cfg.get("server_url") or ""),
            )
            appdata_dir = vw._profile_bw_appdata(get_hermes_home())
        except RuntimeError as exc:
            console.print(f"[red]Authentication failed: {exc}[/red]")
            return 1
    if not session:
        console.print(f"[red]{session_env} is not set.[/red]")
        return 1

    console.print("[dim]Syncing vault from server…[/dim]")
    try:
        child_env = {"BW_SESSION": session}
        if appdata_dir is not None:
            child_env["BITWARDENCLI_APPDATA_DIR"] = str(appdata_dir)
        res = run_secret_cli(
            [str(binary), "sync"],
            allow_env=vw._BW_ALLOW_ENV,
            extra_env=child_env,
            timeout=30,
        )
        if res.returncode != 0:
            err = (res.stderr or res.stdout or "").strip()[:200]
            console.print(f"[yellow]bw sync warning: {err}[/yellow]")
    except RuntimeError as exc:
        console.print(f"[yellow]bw sync skipped: {exc}[/yellow]")

    # Stage the normal full-source orchestration pass in a private mapping.
    # This preserves protected variables, preserve_existing, mapped-vs-bulk
    # precedence, first-claim-wins, and provenance.  --apply controls only
    # whether Vaultwarden-attributed results are committed to this process;
    # it never changes override_existing semantics.
    secrets_cfg = cfg.get("secrets") or {}
    orchestrated_cfg = dict(secrets_cfg) if isinstance(secrets_cfg, dict) else {}
    orchestrated_vw_cfg = dict(vw_cfg)
    orchestrated_vw_cfg["cache_ttl_seconds"] = 0
    orchestrated_cfg["vaultwarden"] = orchestrated_vw_cfg
    staged_env = dict(os.environ)
    staged_env[session_env] = session
    report = secret_registry.apply_all(
        orchestrated_cfg,
        get_hermes_home(),
        environ=staged_env,
    )
    vw_report = next((sr for sr in report.sources if sr.name == "vaultwarden"), None)
    if vw_report is None:
        console.print(
            "[red]Vaultwarden secret source is not registered in the Hermes "
            "orchestrator.[/red]"
        )
        return 1
    if not vw_report.result.ok:
        console.print(f"[red]Fetch failed: {vw_report.result.error}[/red]")
        return 1

    for warning in vw_report.result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    contested = set(vw_report.skipped_claimed)
    for warning in report.conflicts:
        if any(warning.startswith(f"{name}:") for name in contested):
            console.print(f"[yellow]warning:[/yellow] {warning}")

    attributed = {
        name
        for name, provenance in report.provenance.items()
        if provenance.source == "vaultwarden"
    }
    names = sorted(
        set(vw_report.result.secrets)
        | attributed
        | set(vw_report.skipped_existing)
        | set(vw_report.skipped_claimed)
        | set(vw_report.skipped_protected)
        | set(vw_report.skipped_invalid)
    )
    if not names:
        console.print("[yellow]No usable fields in vault item.[/yellow]")
        return 0

    preserve_raw = orchestrated_cfg.get("preserve_existing")
    preserve = {
        name.strip()
        for name in preserve_raw
        if isinstance(name, str) and name.strip()
    } if isinstance(preserve_raw, list) else set()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Field name", style="cyan")
    table.add_column("Action")
    applied = 0
    for key in names:
        if key in attributed:
            provenance = report.provenance.get(key)
            overrode = bool(provenance and provenance.overrode_env)
            if args.apply:
                os.environ[key] = staged_env[key]
                applied += 1
                action = "[green]exported[/green]" + (" (overrode)" if overrode else "")
            else:
                action = "[green]would export[/green]" + (
                    " (overrides)" if overrode else ""
                )
        elif key in vw_report.skipped_protected:
            action = "[dim]skip (protected bootstrap variable)[/dim]"
        elif key in vw_report.skipped_claimed:
            action = "[dim]skip (claimed by another secret source)[/dim]"
        elif key in vw_report.skipped_existing:
            reason = "preserve_existing" if key in preserve else "already set"
            action = f"[dim]skip ({reason})[/dim]"
        elif key in vw_report.skipped_invalid:
            action = "[dim]skip (invalid env-var name)[/dim]"
        else:
            action = "[dim]skip[/dim]"
        table.add_row(key, action)

    console.print(table)

    if not args.apply:
        console.print(
            "\n  Dry-run — secrets are pulled automatically by Hermes processes "
            "spawned after plugin discovery.  Re-run with [cyan]--apply[/cyan] "
            "to export into the current process instead."
        )
    else:
        console.print(f"\n  [green]Exported {applied} secret(s) into current process.[/green]")
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    console = Console()
    cfg = load_config()
    vw_cfg = (cfg.setdefault("secrets", {})
                .setdefault("vaultwarden", {}))
    vw_cfg["enabled"] = False
    save_config(cfg)
    vw._reset_cache_for_tests()  # drop cached secret values from disk
    console.print(
        "[green]Disabled.[/green]  Vaultwarden secrets will NOT be pulled on the next "
        "Hermes invocation.\n"
        "  Your session token is left in .env — remove it manually if desired."
    )
    return 0


def cmd_reset_auth(args: argparse.Namespace) -> int:
    """Log out only the ``bw`` state owned by the active Hermes profile."""
    console = Console()
    cfg = load_config()
    vw_cfg = (cfg.get("secrets") or {}).get("vaultwarden") or {}
    binary = vw.find_bw(vw_cfg.get("binary_path"))
    if binary is None:
        console.print("[red]bw binary not found.[/red]")
        return 1
    appdata_dir = vw._profile_bw_appdata(get_hermes_home())
    try:
        res = vw._run_bw(binary, "logout", appdata_dir=appdata_dir)
    except RuntimeError as exc:
        console.print(f"[red]Could not reset profile authentication: {exc}[/red]")
        return 1
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()[:200]
        if "not logged in" not in err.lower():
            console.print(f"[red]bw logout failed: {err}[/red]")
            return 1
    console.print("[green]Profile authentication reset.[/green] No vault items were changed.")
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _yn(b: bool) -> str:
    return "[green]yes[/green]" if b else "[dim]no[/dim]"


def _bw_version(binary: Path) -> str:
    try:
        res = run_secret_cli([str(binary), "--version"], timeout=5)
        if res.returncode == 0:
            return (res.stdout or res.stderr).strip().splitlines()[0]
    except RuntimeError:
        pass
    return "version unknown"


def _bw_current_server(binary: Path, appdata_dir: Optional[Path] = None) -> str:
    """Return the currently configured bw server URL, or empty string."""
    try:
        child_env = (
            {"BITWARDENCLI_APPDATA_DIR": str(appdata_dir)} if appdata_dir else None
        )
        res = run_secret_cli(
            [str(binary), "config", "server"],
            allow_env=vw._BW_ALLOW_ENV,
            extra_env=child_env,
            timeout=5,
        )
        if res.returncode == 0:
            return (res.stdout or "").strip()
    except RuntimeError:
        pass
    return ""


def _list_items(
    binary: Path,
    session: str,
    console: Console,
    appdata_dir: Optional[Path] = None,
) -> Optional[List[dict]]:
    """Call ``bw list items`` and return items that have custom fields."""
    try:
        child_env = {"BW_SESSION": session}
        if appdata_dir is not None:
            child_env["BITWARDENCLI_APPDATA_DIR"] = str(appdata_dir)
        res = run_secret_cli(
            [str(binary), "list", "items"],
            allow_env=vw._BW_ALLOW_ENV,
            extra_env=child_env,
            timeout=20,
        )
    except RuntimeError as exc:
        console.print(f"  [red]Couldn't list vault items: {exc}[/red]")
        return None

    if res.returncode != 0:
        err = (res.stderr or res.stdout).strip()[:300]
        console.print(f"  [red]bw list items failed: {err}[/red]")
        if "session" in err.lower() or "not logged" in err.lower():
            console.print(
                "  [yellow]Session may have expired.  "
                "Re-unlock with [cyan]bw unlock[/cyan] and re-run setup.[/yellow]"
            )
        return None

    try:
        data = json.loads(res.stdout or "[]")
    except json.JSONDecodeError as exc:
        console.print(f"  [red]bw returned non-JSON: {exc}[/red]")
        return None
    if not isinstance(data, list):
        return []
    # Prefer items with valid env-var custom fields; fall back to all items
    result = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if not item.get("id") or not item.get("name"):
            continue
        fields = item.get("fields") or []
        has_env_fields = any(
            isinstance(f, dict) and is_valid_env_name(f.get("name", ""))
            for f in fields
        )
        if has_env_fields:
            result.append({"id": item["id"], "name": item["name"]})
    if not result:
        result = [
            {"id": item["id"], "name": item["name"]}
            for item in data
            if isinstance(item, dict) and item.get("id") and item.get("name")
        ]
    return result
