"""Vaultwarden / Bitwarden Password Manager (``bw`` CLI) secret source.

Hermes pulls API keys from a Vaultwarden (or Bitwarden) vault item at
process startup.  Vaultwarden implements the Bitwarden Password Manager
API — not Bitwarden Secrets Manager — so the ``bws`` CLI used by the
bundled ``secrets.bitwarden`` source does not work with it.  This plugin
bridges that gap.

Design summary
--------------

* ``bw`` is NOT auto-installed.  Install it from your package manager or
  https://github.com/bitwarden/clients/releases.  Resolution order:
  ``secrets.vaultwarden.binary_path`` (pinned) → ``<hermes_home>/bin/bw``
  → ``PATH``.
* Interactive use can provide a ``BW_SESSION`` token.  Unattended use can
  mint one in memory from a personal API key plus the account master
  password.  Auto-unlock never persists the session token and isolates the
  ``bw`` data directory beneath the active Hermes home.
* Secrets come from a single named vault item::

      bw get item -- "<item_name>"     (BW_SESSION passed via child env)

  Every custom field whose name is a valid env-var identifier is offered
  to the orchestrator.  The item's structural ``login.username``,
  ``login.password`` and ``notes`` are *not* custom fields and are only
  exported when the user opts in via ``username_env`` / ``password_env``
  / ``notes_env`` — there's no default name to guess, so silence beats a
  wrong guess.  :meth:`VaultwardenSource.fetch` never writes
  ``os.environ`` itself.
* Caching is disabled by default because it stores resolved plaintext secret
  values.  When explicitly enabled it is two-layer (in-process dict + disk
  JSON via the shared
  :class:`agent.secret_sources._cache.DiskCache` substrate), written to
  ``<hermes_home>/cache/vaultwarden_cache.json``.
* Failures NEVER block Hermes startup — ``fetch()`` returns a
  :class:`FetchResult` with ``error``/``error_kind`` set.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent.secret_sources._cache import CachedFetch, DiskCache, resolve_cache_home
from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    get_source_environment,
    is_valid_env_name,
    run_secret_cli,
    scrub_ansi,
)

logger = logging.getLogger(__name__)

_BW_RUN_TIMEOUT = 30.0
_DEFAULT_SESSION_ENV = "BW_SESSION"
_DEFAULT_CACHE_TTL = 0.0
_DEFAULT_CLIENT_ID_ENV = "BW_CLIENTID"
_DEFAULT_CLIENT_SECRET_ENV = "BW_CLIENTSECRET"
_DEFAULT_MASTER_PASSWORD_ENV = "BW_MASTER_PASSWORD"

# Node-based ``bw`` supports private certificate authorities through this
# standard variable.  The path is not secret; the CLI state directory is
# supplied explicitly per invocation instead of inherited.
_BW_ALLOW_ENV = ("NODE_EXTRA_CA_CERTS",)

_CacheKey = Tuple[str, str, str, str, str, str]
# (resolved_home, session_fingerprint, item_name,
#  username_env, password_env, notes_env)


def _cache_key_str(cache_key: _CacheKey) -> str:
    _home, session_fp, item_name, username_env, password_env, notes_env = cache_key
    return f"vw|{session_fp}|{item_name}|{username_env}|{password_env}|{notes_env}"


_CACHE: Dict[_CacheKey, CachedFetch] = {}
_DISK_CACHE: DiskCache[_CacheKey] = DiskCache(
    "vaultwarden_cache.json", key_serializer=_cache_key_str
)


def _disk_cache_path(home_path: Optional[Path] = None) -> Path:
    return _DISK_CACHE.path(home_path)


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------


def _hermes_bin_dir() -> Path:
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "bin"


def find_bw(pinned: Optional[str] = None) -> Optional[Path]:
    """Return a path to a usable ``bw`` binary, or None.

    Resolution order:
      1. ``pinned`` (``secrets.vaultwarden.binary_path``) — when set it is
         authoritative: a broken pin returns None rather than silently
         falling back to a different binary.
      2. ``<hermes_home>/bin/bw``
      3. ``shutil.which("bw")`` (system PATH)

    ``bw`` is not auto-installed — users install it themselves.
    """
    if pinned and str(pinned).strip():
        p = Path(str(pinned)).expanduser()
        if p.exists() and os.access(p, os.X_OK):
            return p
        return None
    try:
        managed = _hermes_bin_dir() / ("bw.exe" if os.name == "nt" else "bw")
        if managed.exists() and os.access(managed, os.X_OK):
            return managed
    except Exception:  # noqa: BLE001 — host helper unavailable in bare tests
        pass
    system = shutil.which("bw")
    return Path(system) if system else None


# ---------------------------------------------------------------------------
# Secret fetch
# ---------------------------------------------------------------------------


def _session_fingerprint(session: str) -> str:
    return hashlib.sha256(session.encode("utf-8")).hexdigest()[:16]


def _profile_bw_appdata(home_path: Path) -> Path:
    """Return a private ``bw`` state directory scoped to one Hermes profile."""
    path = home_path / "plugin-data" / "vaultwarden" / "bw-cli"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _safe_env_name(value: object, default: str, config_key: str) -> str:
    candidate = str(value or default).strip()
    if not is_valid_env_name(candidate):
        raise RuntimeError(
            f"secrets.vaultwarden.{config_key} must name a valid environment variable"
        )
    return candidate


def _run_bw(
    binary: Path,
    *args: str,
    appdata_dir: Optional[Path] = None,
    extra_env: Optional[Dict[str, str]] = None,
):
    child_env = dict(extra_env or {})
    if appdata_dir is not None:
        child_env["BITWARDENCLI_APPDATA_DIR"] = str(appdata_dir)
    return run_secret_cli(
        [str(binary), *args],
        allow_env=_BW_ALLOW_ENV,
        extra_env=child_env,
        timeout=_BW_RUN_TIMEOUT,
    )


def _bw_status(binary: Path, appdata_dir: Path) -> dict:
    proc = _run_bw(binary, "status", "--raw", appdata_dir=appdata_dir)
    if proc.returncode != 0:
        err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
        raise RuntimeError(f"bw status failed: {err[:200]}")
    try:
        status = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bw status returned non-JSON output: {exc}") from exc
    if not isinstance(status, dict) or status.get("status") not in {
        "unauthenticated", "locked", "unlocked"
    }:
        raise RuntimeError("bw status returned an unexpected authentication state")
    return status


def mint_session(
    binary: Path,
    *,
    home_path: Path,
    client_id_env: str = _DEFAULT_CLIENT_ID_ENV,
    client_secret_env: str = _DEFAULT_CLIENT_SECRET_ENV,
    master_password_env: str = _DEFAULT_MASTER_PASSWORD_ENV,
    server_url: str = "",
) -> str:
    """Mint a ``bw`` session without prompts or persistent session tokens.

    A personal Bitwarden API key authenticates an unauthenticated CLI; the
    master password decrypts the vault.  Login state is stored in a private
    directory beneath ``home_path`` so Hermes profiles cannot race or inherit
    one another's Bitwarden state.  Credential values travel only in the child
    environment and the returned session exists only in process memory.
    """
    client_id_env = _safe_env_name(client_id_env, _DEFAULT_CLIENT_ID_ENV, "client_id_env")
    client_secret_env = _safe_env_name(
        client_secret_env, _DEFAULT_CLIENT_SECRET_ENV, "client_secret_env"
    )
    master_password_env = _safe_env_name(
        master_password_env, _DEFAULT_MASTER_PASSWORD_ENV, "master_password_env"
    )
    source_env = get_source_environment()
    credentials = {
        client_id_env: str(source_env.get(client_id_env) or "").strip(),
        client_secret_env: str(source_env.get(client_secret_env) or "").strip(),
        master_password_env: str(source_env.get(master_password_env) or "").strip(),
    }
    missing = [name for name, value in credentials.items() if not value]
    if missing:
        raise RuntimeError("auto_unlock requires environment variables: " + ", ".join(missing))

    appdata_dir = _profile_bw_appdata(home_path)
    status = _bw_status(binary, appdata_dir)
    configured_server = str(status.get("serverUrl") or "").rstrip("/")
    requested_server = str(server_url or "").strip().rstrip("/")
    if not requested_server:
        raise RuntimeError(
            "auto_unlock requires an explicit secrets.vaultwarden.server_url"
        )
    if not requested_server.startswith("https://"):
        raise RuntimeError("secrets.vaultwarden.server_url must use HTTPS")
    if requested_server and configured_server and requested_server != configured_server:
        raise RuntimeError(
            "configured bw server does not match secrets.vaultwarden.server_url; "
            "run `hermes vaultwarden reset-auth` before changing servers"
        )
    if requested_server and not configured_server:
        if status["status"] != "unauthenticated":
            raise RuntimeError("bw server cannot be changed while the profile is authenticated")
        proc = _run_bw(
            binary, "config", "server", requested_server, appdata_dir=appdata_dir
        )
        if proc.returncode != 0:
            err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
            raise RuntimeError(f"bw config server failed: {err[:200]}")
        persisted = str(_bw_status(binary, appdata_dir).get("serverUrl") or "").rstrip("/")
        if persisted != requested_server:
            raise RuntimeError(
                "bw did not persist the configured server in the profile state directory; "
                "use the standalone Bitwarden CLI or grant the sandboxed CLI access to "
                "the Hermes profile directory"
            )

    if status["status"] == "unauthenticated":
        proc = _run_bw(
            binary,
            "login",
            "--apikey",
            appdata_dir=appdata_dir,
            extra_env={
                "BW_CLIENTID": credentials[client_id_env],
                "BW_CLIENTSECRET": credentials[client_secret_env],
            },
        )
        if proc.returncode != 0:
            err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
            raise RuntimeError(f"bw API-key login failed: {err[:200]}")

    proc = _run_bw(
        binary,
        "unlock",
        "--passwordenv",
        master_password_env,
        "--raw",
        appdata_dir=appdata_dir,
        extra_env={master_password_env: credentials[master_password_env]},
    )
    if proc.returncode != 0:
        err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
        raise RuntimeError(f"bw unlock failed: {err[:200]}")
    session = (proc.stdout or "").strip()
    if not session:
        raise RuntimeError("bw unlock --raw returned an empty session token")
    return session


def fetch_vaultwarden_secrets(
    *,
    session: str,
    item_name: str,
    binary: Optional[Path] = None,
    cache_ttl_seconds: float = _DEFAULT_CACHE_TTL,
    use_cache: bool = True,
    home_path: Optional[Path] = None,
    username_env: Optional[str] = None,
    password_env: Optional[str] = None,
    notes_env: Optional[str] = None,
    appdata_dir: Optional[Path] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Pull secrets from a vault item via ``bw get item``.

    Every custom field becomes an env var.  ``login.username``,
    ``login.password`` and ``notes`` are structural (not custom fields)
    and are only included when the caller opts in via ``username_env`` /
    ``password_env`` / ``notes_env`` — the target env-var name for each.

    Returns ``(secrets_dict, warnings_list)``.

    Raises :class:`RuntimeError` for fatal conditions (missing binary,
    auth failure, unknown item, unparseable output).
    """
    if not session:
        raise RuntimeError("Vaultwarden session token is empty")
    if not item_name:
        raise RuntimeError("Vaultwarden item_name is empty")

    cache_key: _CacheKey = (
        str(resolve_cache_home(home_path)),
        _session_fingerprint(session),
        item_name,
        username_env or "",
        password_env or "",
        notes_env or "",
    )
    if use_cache:
        cached = _CACHE.get(cache_key)
        if cached and cached.is_fresh(cache_ttl_seconds):
            return cached.secrets, []
        disk_cached = _DISK_CACHE.read(cache_key, cache_ttl_seconds, home_path)
        if disk_cached is not None:
            _CACHE[cache_key] = disk_cached
            return disk_cached.secrets, []

    bw = binary or find_bw()
    if bw is None:
        raise RuntimeError(
            "bw binary not found.  Install it from your package manager or "
            "https://github.com/bitwarden/clients/releases"
        )

    secrets, warnings = _run_bw_get_item(
        bw,
        session,
        item_name,
        username_env=username_env,
        password_env=password_env,
        notes_env=notes_env,
        appdata_dir=appdata_dir,
    )
    import time as _time

    entry = CachedFetch(secrets=secrets, fetched_at=_time.time())
    if use_cache and cache_ttl_seconds > 0:
        _CACHE[cache_key] = entry
        _DISK_CACHE.write(cache_key, entry, cache_ttl_seconds, home_path)
    return secrets, warnings


def _run_bw_get_item(
    bw: Path,
    session: str,
    item_name: str,
    *,
    username_env: Optional[str] = None,
    password_env: Optional[str] = None,
    notes_env: Optional[str] = None,
    appdata_dir: Optional[Path] = None,
) -> Tuple[Dict[str, str], List[str]]:
    # Session travels via the child env (bw reads BW_SESSION natively)
    # instead of a --session argv flag, keeping the token out of
    # /proc/<pid>/cmdline.  NOTE: no `--` terminator here — bw 2026.7.0's
    # `get item` rejects the terminator ("Not found."), so the item name
    # is passed directly. bw's CLI does not treat a plain search term
    # starting with "-" as a flag for this command.
    child_env = {"BW_SESSION": session}
    if appdata_dir is not None:
        child_env["BITWARDENCLI_APPDATA_DIR"] = str(appdata_dir)
    proc = run_secret_cli(
        [str(bw), "get", "item", item_name],
        allow_env=_BW_ALLOW_ENV,
        extra_env=child_env,
        timeout=_BW_RUN_TIMEOUT,
    )

    if proc.returncode != 0:
        err = scrub_ansi((proc.stderr or proc.stdout or "")).strip()
        raise RuntimeError(f"bw exited {proc.returncode}: {err[:200]}")

    raw = (proc.stdout or "").strip()
    if not raw:
        return {}, ["bw returned no output"]

    try:
        item = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"bw returned non-JSON output: {exc}") from exc

    if not isinstance(item, dict):
        raise RuntimeError(f"bw returned unexpected shape: {type(item).__name__}")

    fields = item.get("fields") or []
    if not isinstance(fields, list):
        fields = []

    secrets: Dict[str, str] = {}
    warnings: List[str] = []
    for f in fields:
        if not isinstance(f, dict):
            continue
        name = f.get("name")
        value = f.get("value")
        if not isinstance(name, str) or value is None:
            continue
        value = str(value)
        if not is_valid_env_name(name):
            warnings.append(f"Skipping field {name!r}: not a valid env-var name")
            continue
        secrets[name] = value

    if not fields and not (username_env or password_env or notes_env):
        return {}, [
            "item has no custom fields — add fields named after the env vars "
            "you want to export, or set username_env/password_env/notes_env "
            "to pull the login/notes values instead"
        ]

    login = item.get("login")
    login = login if isinstance(login, dict) else {}
    for env_name, value, label in (
        (username_env, login.get("username"), "login.username"),
        (password_env, login.get("password"), "login.password"),
        (notes_env, item.get("notes"), "notes"),
    ):
        if not env_name:
            continue
        if value is None or value == "":
            warnings.append(f"item has no {label} to export as {env_name}")
            continue
        if env_name in secrets:
            warnings.append(
                f"{env_name} set by both a custom field and {label} — "
                f"{label} wins"
            )
        secrets[env_name] = str(value)

    return secrets, warnings


# ---------------------------------------------------------------------------
# Error classification — maps RuntimeError text onto the ErrorKind taxonomy
# ---------------------------------------------------------------------------


def _classify_bw_error(message: str) -> ErrorKind:
    lowered = (message or "").lower()
    if any(
        token in lowered
        for token in (
            "requires environment variables",
            "must name a valid environment",
            "requires an explicit secrets.vaultwarden.server_url",
            "server_url must use https",
        )
    ):
        return ErrorKind.NOT_CONFIGURED
    if "timed out" in lowered:
        return ErrorKind.TIMEOUT
    if "failed to invoke" in lowered or "binary not found" in lowered:
        return ErrorKind.BINARY_MISSING
    if any(
        tok in lowered
        for tok in (
            "api-key login failed",
            "invalid client",
            "invalid master password",
            "credentials rejected",
        )
    ):
        return ErrorKind.AUTH_FAILED
    if any(tok in lowered for tok in (
        "session", "unlock", "not logged in", "vault is locked", "locked",
        "unauthorized", "mac failed",
    )):
        return ErrorKind.AUTH_EXPIRED
    if "not found" in lowered or "more than one result" in lowered:
        return ErrorKind.REF_INVALID
    if any(tok in lowered for tok in (
        "network", "connection", "resolve host", "dns",
        "econnrefused", "enotfound", "etimedout",
    )):
        return ErrorKind.NETWORK
    return ErrorKind.INTERNAL


def resolve_login_bindings(
    cfg: dict,
) -> Tuple[Dict[str, Optional[str]], List[str]]:
    """Validate cfg's username_env/password_env/notes_env.

    Returns ``(bindings, warnings)``.  Empty/missing -> ``None`` (opt-out,
    the default).  Non-empty but not a valid env-var name -> ``None`` plus
    a warning — never raises; callers embed the warning into their own
    reporting.
    """
    bindings: Dict[str, Optional[str]] = {}
    warnings: List[str] = []
    for key in ("username_env", "password_env", "notes_env"):
        raw = str(cfg.get(key) or "").strip()
        if not raw:
            bindings[key] = None
        elif is_valid_env_name(raw):
            bindings[key] = raw
        else:
            bindings[key] = None
            warnings.append(
                f"secrets.vaultwarden.{key} {raw!r} is not a valid "
                "env-var name — ignoring it"
            )
    return bindings, warnings


# ---------------------------------------------------------------------------
# The SecretSource — registered via PluginContext.register_secret_source()
# ---------------------------------------------------------------------------


class VaultwardenSource(SecretSource):
    """Vaultwarden vault-item custom fields as env vars.

    A **bulk** source: the user names one vault item and every custom
    field of that item is offered implicitly — there is no per-var
    VAR→ref binding, so explicit mapped bindings (e.g. 1Password
    ``env:`` entries) rightly outrank it on contested vars.
    """

    name = "vaultwarden"
    label = "Vaultwarden"
    shape = "bulk"
    scheme = None

    def protected_env_vars(self, cfg: dict):
        cfg = cfg if isinstance(cfg, dict) else {}
        protected = set()
        for key, default in (
            ("session_env", _DEFAULT_SESSION_ENV),
            ("client_id_env", _DEFAULT_CLIENT_ID_ENV),
            ("client_secret_env", _DEFAULT_CLIENT_SECRET_ENV),
            ("master_password_env", _DEFAULT_MASTER_PASSWORD_ENV),
        ):
            candidate = str(cfg.get(key) or default)
            if is_valid_env_name(candidate):
                protected.add(candidate)
        return frozenset(protected)

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "session_env": {
                "description": "Env var holding the `bw` session token",
                "default": _DEFAULT_SESSION_ENV,
            },
            "auto_unlock": {
                "description": (
                    "When true and no session token is present in session_env, "
                    "authenticate with a personal API key and mint a session in "
                    "memory. The token is never persisted."
                ),
                "default": False,
            },
            "client_id_env": {
                "description": "Env var holding the personal API-key client ID",
                "default": _DEFAULT_CLIENT_ID_ENV,
            },
            "client_secret_env": {
                "description": "Env var holding the personal API-key client secret",
                "default": _DEFAULT_CLIENT_SECRET_ENV,
            },
            "master_password_env": {
                "description": "Env var holding the account master password",
                "default": _DEFAULT_MASTER_PASSWORD_ENV,
            },
            "server_url": {
                "description": "Vaultwarden server URL for this Hermes profile",
                "default": "",
            },
            "item_id": {
                "description": "Preferred immutable vault item ID",
                "default": "",
            },
            "item_name": {
                "description": "Vault item whose custom fields become env vars",
                "default": "",
            },
            "username_env": {
                "description": (
                    "Env var to export the item's login.username as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "password_env": {
                "description": (
                    "Env var to export the item's login.password as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "notes_env": {
                "description": (
                    "Env var to export the item's notes as.  "
                    "Empty (default) means don't export it."
                ),
                "default": "",
            },
            "override_existing": {
                "description": (
                    "Overwrite env vars already set by .env / the shell.  "
                    "Defaults to False (bundled sources default True) — "
                    "preserves the historical in-tree behaviour."
                ),
                "default": False,
            },
            "cache_ttl_seconds": {
                "description": "Cache TTL for both cache layers; 0 disables caching",
                "default": int(_DEFAULT_CACHE_TTL),
            },
            "binary_path": {
                "description": "Pin an exact bw binary path (skips PATH lookup)",
                "default": "",
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}

        try:
            session_env = _safe_env_name(
                cfg.get("session_env"), _DEFAULT_SESSION_ENV, "session_env"
            )
        except RuntimeError as exc:
            result.error = str(exc)
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result
        session = str(get_source_environment().get(session_env) or "").strip()

        auto_unlock = bool(cfg.get("auto_unlock", False))
        appdata_dir: Optional[Path] = None
        if not session and auto_unlock:
            binary0 = find_bw(cfg.get("binary_path"))
            if binary0 is None:
                result.error = (
                    "bw binary not found.  Install it from your package manager or "
                    "https://github.com/bitwarden/clients/releases"
                )
                result.error_kind = ErrorKind.BINARY_MISSING
                return result
            try:
                session = mint_session(
                    binary0,
                    home_path=home_path,
                    client_id_env=str(cfg.get("client_id_env") or _DEFAULT_CLIENT_ID_ENV),
                    client_secret_env=str(
                        cfg.get("client_secret_env") or _DEFAULT_CLIENT_SECRET_ENV
                    ),
                    master_password_env=str(
                        cfg.get("master_password_env") or _DEFAULT_MASTER_PASSWORD_ENV
                    ),
                    server_url=str(cfg.get("server_url") or ""),
                )
                appdata_dir = _profile_bw_appdata(home_path)
                result.warnings.append("auto_unlock: minted an in-memory session")
            except RuntimeError as exc:
                result.error = str(exc)
                result.error_kind = _classify_bw_error(str(exc))
                return result

        if not session:
            result.error = (
                f"secrets.vaultwarden.enabled is true but {session_env} is not "
                "set. Run `hermes vaultwarden setup`, or set "
                "secrets.vaultwarden.auto_unlock=true to mint a session from "
                "a personal API key and master password."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        item_name = str(cfg.get("item_id") or cfg.get("item_name") or "").strip()
        if not item_name:
            result.error = (
                "secrets.vaultwarden.item_id/item_name is empty.  "
                "Run `hermes vaultwarden setup`."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        binary = find_bw(cfg.get("binary_path"))
        result.binary_path = binary
        if binary is None:
            result.error = (
                "bw binary not found.  Install it from your package manager or "
                "https://github.com/bitwarden/clients/releases"
            )
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        try:
            ttl = float(cfg.get("cache_ttl_seconds", _DEFAULT_CACHE_TTL))
        except (TypeError, ValueError):
            ttl = _DEFAULT_CACHE_TTL

        login_bindings, binding_warnings = resolve_login_bindings(cfg)
        result.warnings.extend(binding_warnings)

        try:
            secrets, warnings = fetch_vaultwarden_secrets(
                session=session,
                item_name=item_name,
                binary=binary,
                cache_ttl_seconds=ttl,
                home_path=home_path,
                username_env=login_bindings["username_env"],
                password_env=login_bindings["password_env"],
                notes_env=login_bindings["notes_env"],
                appdata_dir=appdata_dir,
            )
        except RuntimeError as exc:
            result.error = str(exc)
            result.error_kind = _classify_bw_error(str(exc))
            return result
        except Exception as exc:  # noqa: BLE001 — contract: never raise
            result.error = f"unexpected error: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

        result.secrets = secrets
        result.warnings.extend(warnings)
        return result


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------


def _reset_cache_for_tests(home_path: Optional[Path] = None) -> None:
    _CACHE.clear()
    _DISK_CACHE.clear(home_path)
