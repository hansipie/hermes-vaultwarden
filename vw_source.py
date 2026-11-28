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
  password.  Auto-unlock never persists the session token, ignores any
  ``BW_SESSION`` from the environment, and isolates the ``bw`` data
  directory beneath the active Hermes home.
* Secrets come from a single named vault item.  On every cache miss the
  profile-local CLI vault is synchronized before the item is read::

      bw sync
      bw get item "<item_name>"        (BW_SESSION passed via child env)

  A failed sync fails the source fetch instead of silently applying stale
  credentials from the CLI's local encrypted vault.

  ``bw`` rejects the usual ``--`` option terminator for this command, so
  item references beginning with ``-`` are rejected before invocation.

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

from contextlib import contextmanager
import hashlib
import json
import logging
import threading
import os
import signal
import subprocess
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

from agent.secret_sources._cache import CachedFetch, DiskCache, resolve_cache_home
from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    get_source_environment,
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
# fetch() skips the network sync when the CLI state synced less than this
# many seconds ago.  fetch_vaultwarden_secrets() itself defaults to 0
# (always sync) for direct callers such as the setup wizard.
_DEFAULT_SYNC_INTERVAL = 300.0
_DEFAULT_CLIENT_ID_ENV = "BW_CLIENTID"
_DEFAULT_CLIENT_SECRET_ENV = "BW_CLIENTSECRET"
_DEFAULT_MASTER_PASSWORD_ENV = "BW_MASTER_PASSWORD"

# Node-based ``bw`` supports private certificate authorities through
# ``NODE_EXTRA_CA_CERTS``.  ``BITWARDENCLI_APPDATA_DIR`` is inherited so
# session-mode users who relocated bw's data dir keep reading the vault
# their token was issued for.  In auto_unlock mode every invocation passes
# the isolated profile dir through ``extra_env``, which overrides the
# inherited value.  Neither path is secret.
_BW_ALLOW_ENV = ("NODE_EXTRA_CA_CERTS", "BITWARDENCLI_APPDATA_DIR")

# Key: resolved profile appdata path, resolved binary path, normalized server URL,
# three credential environment-variable names, then SHA-256 fingerprints of
# their effective values (client ID and secret stripped; master password verbatim).
# This cache contains session tokens in process memory only, separate from item caches.
_AUTH_SESSIONS: dict = {}
# Reset increments a profile generation, fencing publication by older fetches.
_AUTH_GENERATIONS: dict = {}
# Counts keep overlapping resets fenced until the last logout completes.
_AUTH_RESETTING: dict = {}
_AUTH_LOCK = threading.RLock()


def _clear_auth_sessions(appdata_dir: Path) -> None:
    profile = str(Path(appdata_dir).resolve())
    with _AUTH_LOCK:
        _AUTH_GENERATIONS[profile] = _AUTH_GENERATIONS.get(profile, 0) + 1
        for key in list(_AUTH_SESSIONS):
            if key[0] == profile:
                _AUTH_SESSIONS.pop(key, None)


@contextmanager
def _reset_auth_transaction(appdata_dir: Path):
    profile = str(Path(appdata_dir).resolve())
    with _AUTH_LOCK:
        _AUTH_RESETTING[profile] = _AUTH_RESETTING.get(profile, 0) + 1
        _clear_auth_sessions(appdata_dir)
    try:
        yield
    finally:
        with _AUTH_LOCK:
            _clear_auth_sessions(appdata_dir)
            _AUTH_RESETTING[profile] -= 1
            if not _AUTH_RESETTING[profile]:
                del _AUTH_RESETTING[profile]


# Upper bound on bw output carried inside an exception.  Callers redact
# before truncating further, so this only stops arbitrarily large output.
_ERR_CAP = 4096

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_TOKEN_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9_+/=-])"
)


def _bw_error_text(proc) -> str:
    """stderr-or-stdout of a failed bw call, ANSI-scrubbed and bounded."""
    return scrub_ansi(proc.stderr or proc.stdout or "").strip()[:_ERR_CAP]


def _looks_like_token(candidate: str) -> bool:
    # Item UUIDs and identifier-like strings stay readable: separator-joined
    # segments that are each single-case (snake_case / UPPER_CASE env names,
    # kebab-case, lowercase path segments).  Anything else of token length
    # (base64 session keys, unseparated blobs) is treated as a secret.
    if _UUID_RE.fullmatch(candidate):
        return False
    segments = [s for s in re.split(r"[_/-]+", candidate) if s]
    if len(segments) < 2 or any(c in candidate for c in "+="):
        return True
    return any(s != s.lower() and s != s.upper() for s in segments)


def _safe_diagnostic(
    text: str, values, session_env: str = _DEFAULT_SESSION_ENV, *, generic: bool = True
) -> str:
    """Redact secrets from a diagnostic.

    Known ``values`` and labelled session patterns are always redacted.
    ``generic`` additionally redacts unlabelled token-shaped strings; it is
    meant for raw bw output and is disabled for plugin-built warnings.
    """
    text = scrub_ansi(str(text))
    for value in sorted({str(v) for v in values if v}, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    # Preserve upstream stderr-or-stdout fallback; redact contextual session values
    # from either stream, including the configured session environment name.
    labels = r"[A-Z0-9_]*SESSION|" + re.escape(session_env)
    text = re.sub(
        rf"(?i)((?:--session\s+|\b(?:{labels})\s*[:=]\s*)[\"']?)([^\s\"']+)",
        r"\1[REDACTED]", text,
    )
    text = re.sub(r"(?i)(\bsession\s+)([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)", r"\1[REDACTED]", text)
    if not generic:
        return text
    # Tokens are commonly long base64/base64url strings, including padded ones.
    return _TOKEN_CANDIDATE_RE.sub(
        lambda m: "[REDACTED]" if _looks_like_token(m.group(0)) else m.group(0), text
    )


def cli_safe_error(exc: object, session: str = "") -> str:
    """Redacted, bounded rendering of an exception for direct CLI callers.

    ``mint_session`` and ``fetch_vaultwarden_secrets`` raise with full bw
    output so ``VaultwardenSource.fetch`` can redact before truncating;
    callers printing those exceptions must apply the same guarantee.
    """
    env = get_source_environment()
    values = [session] + [
        str(env.get(name) or "")
        for name in (_DEFAULT_CLIENT_ID_ENV, _DEFAULT_CLIENT_SECRET_ENV,
                     _DEFAULT_MASTER_PASSWORD_ENV, _DEFAULT_SESSION_ENV)
    ]
    values += [v.strip() for v in values]
    return _safe_diagnostic(str(exc), values)[:500]


# ---------------------------------------------------------------------------
# Config ${VAR} / ${env:VAR} expansion (plugin-side, mirrors hermes_cli/config.py)
# ---------------------------------------------------------------------------
# Core intentionally reads the ``secrets:`` section RAW (_load_secrets_config →
# read_raw_config; no _expand_env_vars on that path), and core's own expander
# only handles the env shape ("external backends inject their values into the
# environment at startup, so a config ref only ever needs the env shape"). The
# bulk Vaultwarden source must therefore do the same expansion itself or a
# config like ``item_name: ${BW_ITEM_NAME}`` reaches `bw get item` as a
# literal template (observed: "bw exited 1: Not found." twice per boot).
_ENV_REF_RE = re.compile(r"\$\{([^}]+)\}")


def _env_ref_var_name(inner: str) -> Optional[str]:
    """Var name for ``${VAR}`` (bare name) or ``${env:VAR}``; None otherwise."""
    inner = inner.strip()
    if inner.startswith("env:"):
        inner = inner[4:].strip()
    return inner if inner.isidentifier() else None


def _env_ref_lookup(name: str) -> Optional[str]:
    """Resolve an env var for a config ref from the source environment.

    ``get_source_environment()`` is the per-fetch view (apply_all's
    ``environ``) when one is active and ``os.environ`` otherwise.  There is
    deliberately no fallback to ``os.environ`` when the per-fetch view lacks
    the var: in multiplex mode that would pick up another profile's value.
    """
    return get_source_environment().get(name)


def _expand_env_refs_tracked(value: str) -> Tuple[str, List[str]]:
    """Expand ``${VAR}``/``${env:VAR}`` and report the names left unresolved.

    Unresolved refs stay verbatim (same policy as core's _expand_env_vars).
    Non-env refs such as ``${file:…}`` are left untouched and are not
    reported, and a resolved value that itself contains ``${`` is kept as is.
    """
    missing: List[str] = []

    def _sub(m: "re.Match[str]") -> str:
        name = _env_ref_var_name(m.group(1))
        if name is None:
            return m.group(0)
        val = _env_ref_lookup(name)
        if val is None:
            if name not in missing:
                missing.append(name)
            return m.group(0)
        return val

    return _ENV_REF_RE.sub(_sub, value), missing


def _expand_env_refs(value: str) -> str:
    """Expand ``${VAR}``/``${env:VAR}``; unresolved refs stay verbatim."""
    return _expand_env_refs_tracked(value)[0]


def resolve_item_name(cfg: dict) -> Tuple[str, Optional[str]]:
    """Return ``(item_ref, error)`` for the configured vault item.

    ``item_id`` wins over ``item_name``.  ``${VAR}``/``${env:VAR}`` refs are
    expanded because the ``secrets:`` section reaches the plugin raw.  On
    failure ``item_ref`` is empty and ``error`` says what is wrong, naming
    the unset variables.  Shared by :meth:`VaultwardenSource.fetch` and the
    ``hermes vaultwarden`` CLI so both resolve the same item.
    """
    cfg = cfg if isinstance(cfg, dict) else {}
    key = "item_id" if str(cfg.get("item_id") or "").strip() else "item_name"
    raw = str(cfg.get(key) or "").strip()
    if not raw:
        return "", (
            "secrets.vaultwarden.item_id/item_name is empty.  "
            "Run `hermes vaultwarden setup`."
        )
    expanded, missing = _expand_env_refs_tracked(raw)
    if missing:
        refs = ", ".join("${" + name + "}" for name in missing)
        verb = "is" if len(missing) == 1 else "are"
        return "", (
            f"secrets.vaultwarden.{key} references {refs}, which {verb} not set.  "
            "Set it in the environment (envdir/.env) or run "
            "`hermes vaultwarden setup`."
        )
    expanded = expanded.strip()
    if not expanded:
        return "", (
            f"secrets.vaultwarden.{key} expands to an empty value.  "
            "Run `hermes vaultwarden setup`."
        )
    return expanded, None


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


# credentials_command: a user-configured, non-interactive helper (secret-tool,
# pass, keepassxc-cli, ...) that prints the auto-unlock credentials as
# KEY=VALUE lines.  Values stay in this process's memory: never written to
# .env, os.environ or disk, and never logged.  Semantics mirror Hermes' own
# ``command`` secret source (which cannot serve these values: apply_all
# fetches every source before applying any, and these names are protected).
_CRED_CMD_TIMEOUT = 5.0
_CRED_CMD_MAX_OUTPUT = 64 * 1024
_CRED_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _credential_command_env() -> Dict[str, str]:
    # Same environment Hermes gives its own command helper (the user's env,
    # e.g. DBUS_SESSION_BUS_ADDRESS for secret-tool); per-profile under multiplex.
    try:
        from agent.secret_sources.base import source_child_env
        return dict(source_child_env())
    except Exception:  # older Hermes without the helper
        return dict(get_source_environment())


def run_credentials_command(
    command: str, names, *, timeout: float = _CRED_CMD_TIMEOUT
) -> Dict[str, str]:
    """Run ``command`` via ``/bin/sh -c`` and return the requested ``names``.

    Only names in ``names`` are kept; everything else in the output is
    ignored.  stderr is discarded and failures report structured fields
    only (exit code, timeout), never the command, its output or a value.
    A value is used verbatim except for one layer of matching surrounding
    quotes, so leading/trailing spaces in a master password survive.
    """
    if os.name == "nt":
        raise RuntimeError("credentials_command is POSIX-only (needs /bin/sh)")
    wanted = set(names)
    try:
        proc = subprocess.Popen(
            ["/bin/sh", "-c", command], env=_credential_command_env(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError(f"credentials_command failed to start: errno={exc.errno}") from None
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.communicate()
        raise RuntimeError(f"credentials_command timed out after {timeout:g}s") from None
    if proc.returncode != 0:
        raise RuntimeError(f"credentials_command failed: exit code {proc.returncode}")
    if len(out) > _CRED_CMD_MAX_OUTPUT:
        raise RuntimeError("credentials_command output exceeded the size cap")
    values: Dict[str, str] = {}
    for line in out.decode("utf-8", errors="replace").split("\n"):
        m = _CRED_LINE.match(line.rstrip("\r"))
        if not m or m.group(1) not in wanted:
            continue
        value = m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value:
            values[m.group(1)] = value
    return values


def resolve_auto_unlock_credentials(
    names, env: Mapping[str, str], command: object = "", timeout: object = None
) -> Tuple[Dict[str, str], List[str]]:
    """Auto-unlock credential values for ``names``, shared by fetch() and setup.

    ``env`` wins; ``command`` (``credentials_command``) runs only when a name
    is missing and fills just those.  Returns ``(values, filled_names)`` where
    ``filled_names`` came from the command.  Raises RuntimeError from the
    helper (structured message, never a value).  Nothing is written anywhere.
    """
    values = {name: str(env.get(name) or "") for name in names}
    filled: List[str] = []
    command = str(command or "").strip()
    if command and not all(values.values()):
        try:
            seconds = float(timeout) if timeout is not None else _CRED_CMD_TIMEOUT
        except (TypeError, ValueError):
            seconds = _CRED_CMD_TIMEOUT
        from_command = run_credentials_command(command, names, timeout=seconds)
        for name in names:
            if not values[name] and from_command.get(name):
                values[name] = from_command[name]
                filled.append(name)
    return values, filled


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


def _last_sync_age(binary: Path, appdata_dir: Optional[Path]) -> Optional[float]:
    """Seconds since the CLI state's last successful ``bw sync``, or None.

    ``bw status`` is local (no network).  Any doubt (failed call, missing or
    unparsable ``lastSync``, a timestamp in the future) returns None, which
    makes the caller sync.
    """
    try:
        proc = _run_bw(binary, "status", "--raw", appdata_dir=appdata_dir)
    except RuntimeError:
        return None
    if proc.returncode != 0:
        return None
    try:
        status = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    last_sync = status.get("lastSync") if isinstance(status, dict) else None
    if not isinstance(last_sync, str) or not last_sync.strip():
        return None
    try:
        stamp = datetime.fromisoformat(last_sync.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return age if age >= 0 else None


def _sync_bw_vault(
    binary: Path,
    session: str,
    *,
    appdata_dir: Optional[Path] = None,
    min_interval_seconds: float = 0.0,
) -> bool:
    """Refresh the CLI's encrypted local vault before reading an item.

    ``bw get item`` reads local CLI state and does not implicitly contact the
    server.  Without this sync, an unattended profile can keep serving a
    rotated or corrected credential indefinitely across process restarts.

    With ``min_interval_seconds > 0`` the network sync is skipped when the
    state was synced more recently than that (by this or another process),
    which bounds staleness while avoiding a round-trip on every startup.
    Returns True when a sync ran.
    """
    if min_interval_seconds > 0:
        age = _last_sync_age(binary, appdata_dir)
        if age is not None and age < min_interval_seconds:
            return False
    proc = _run_bw(
        binary,
        "sync",
        appdata_dir=appdata_dir,
        extra_env={"BW_SESSION": session},
    )
    if proc.returncode != 0:
        err = _bw_error_text(proc)
        raise RuntimeError(f"bw sync failed: {err}")
    return True


def _bw_status(binary: Path, appdata_dir: Path) -> dict:
    proc = _run_bw(binary, "status", "--raw", appdata_dir=appdata_dir)
    if proc.returncode != 0:
        err = _bw_error_text(proc)
        raise RuntimeError(f"bw status failed: {err}")
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
    credentials_env: Optional[Mapping[str, str]] = None,
) -> str:
    """Mint a ``bw`` session without prompts or persistent session tokens.

    A personal Bitwarden API key authenticates an unauthenticated CLI; the
    master password decrypts the vault.  Login state is stored in a private
    directory beneath ``home_path`` so Hermes profiles cannot race or inherit
    one another's Bitwarden state.  Credential values travel only in the child
    environment and the returned session exists only in process memory.

    ``credentials_env`` replaces the source environment as the place the
    three credential names are read from (e.g. values merged from
    ``credentials_command``); it is never written anywhere.
    """
    client_id_env = _safe_env_name(client_id_env, _DEFAULT_CLIENT_ID_ENV, "client_id_env")
    client_secret_env = _safe_env_name(
        client_secret_env, _DEFAULT_CLIENT_SECRET_ENV, "client_secret_env"
    )
    master_password_env = _safe_env_name(
        master_password_env, _DEFAULT_MASTER_PASSWORD_ENV, "master_password_env"
    )
    source_env = credentials_env if credentials_env is not None else get_source_environment()
    credentials = {
        client_id_env: str(source_env.get(client_id_env) or "").strip(),
        client_secret_env: str(source_env.get(client_secret_env) or "").strip(),
        # Passed through verbatim: leading/trailing spaces can be part of
        # a master password, and --passwordenv reads the exact value.
        master_password_env: str(source_env.get(master_password_env) or ""),
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
            err = _bw_error_text(proc)
            raise RuntimeError(f"bw config server failed: {err}")
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
            err = _bw_error_text(proc)
            raise RuntimeError(f"bw API-key login failed: {err}")

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
        err = scrub_ansi(proc.stderr or "").strip()[:_ERR_CAP]
        raise RuntimeError(f"bw unlock failed: {err}")
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
    sync_interval_seconds: float = 0.0,
    force_read: bool = False,
) -> Tuple[Dict[str, str], List[str]]:
    """Pull secrets from a vault item via ``bw get item``.

    Every custom field becomes an env var.  ``login.username``,
    ``login.password`` and ``notes`` are structural (not custom fields)
    and are only included when the caller opts in via ``username_env`` /
    ``password_env`` / ``notes_env`` — the target env-var name for each.

    Returns ``(secrets_dict, warnings_list)``. ``force_read`` bypasses cached
    plaintext reads while retaining normal cache writes, to prove a new token.

    Raises :class:`RuntimeError` for fatal conditions (missing binary,
    auth failure, unknown item, unparseable output).
    """
    if not session:
        raise RuntimeError("Vaultwarden session token is empty")
    if not item_name:
        raise RuntimeError("Vaultwarden item_name is empty")
    if item_name.startswith("-"):
        raise RuntimeError("Vaultwarden item reference cannot begin with '-'")

    cache_key: _CacheKey = (
        str(resolve_cache_home(home_path)),
        _session_fingerprint(session),
        item_name,
        username_env or "",
        password_env or "",
        notes_env or "",
    )
    if use_cache and not force_read:
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

    _sync_bw_vault(
        bw, session, appdata_dir=appdata_dir,
        min_interval_seconds=sync_interval_seconds,
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
    # /proc/<pid>/cmdline.  NOTE: no `--` terminator here — bw 2026.8.0's
    # `get item` rejects the terminator ("Not found."), so option-shaped
    # item references are rejected by fetch_vaultwarden_secrets() before
    # this command is built.
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
        err = _bw_error_text(proc)
        raise RuntimeError(f"bw exited {proc.returncode}: {err}")

    raw = (proc.stdout or "").strip()
    if not raw:
        # A locked vault / stale BW_SESSION makes bw prompt for the master
        # password; with stdin on /dev/null its readline crashes yet bw
        # still exits 0 with empty stdout.  Treat that as fatal (and never
        # cache it) instead of a silent "no fields" warning.
        err = scrub_ansi(proc.stderr or "").strip()[:_ERR_CAP]
        if "master password" in err.lower():
            raise RuntimeError(
                "vault is locked or the session token is stale — run "
                "`bw unlock --raw` and update BW_SESSION"
            )
        detail = f": {err}" if err else ""
        raise RuntimeError(f"bw returned no output{detail}")

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
        if not isinstance(name, str):
            continue
        if not is_valid_env_name(name):
            warnings.append(f"Skipping field {name!r}: not a valid env-var name")
            continue
        if value is None or str(value) == "":
            warnings.append(f"Skipping field {name!r}: value is empty")
            continue
        value = str(value)
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
    lowered = scrub_ansi(message or "")[:200].lower()
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
    # bw echoes the item reference in "not found" errors, so an item named
    # e.g. "session-backup" must not trip the generic auth keywords below
    # (which, with remint_on_auth_expired, would evict and re-mint a session).
    # Only unambiguous auth phrases take precedence over a missing reference.
    if ("not found" in lowered or "more than one result" in lowered) and not any(
        tok in lowered for tok in (
            "not logged in", "vault is locked", "session expired",
            "session key", "invalid session", "unauthorized", "mac failed",
        )
    ):
        return ErrorKind.REF_INVALID
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


# Hermes strips from every spawned child (terminal tool, subprocesses) any env
# var that config.yaml names through a ``*_secret_env`` / ``*_password_env``
# field (local_env_policy._config_declared_key_envs).  That only works when
# the field is written in config.yaml: a default applied in code is invisible
# to that scan.  BW_SESSION is covered separately through token_env_key.
_CREDENTIAL_POINTER_KEYS = (
    ("client_secret_env", _DEFAULT_CLIENT_SECRET_ENV),
    ("master_password_env", _DEFAULT_MASTER_PASSWORD_ENV),
)


def credential_pointer_defaults() -> Dict[str, str]:
    """Pointer fields ``setup --auto-unlock`` writes so Hermes strips them."""
    return {
        "client_id_env": _DEFAULT_CLIENT_ID_ENV,
        **dict(_CREDENTIAL_POINTER_KEYS),
    }


def undeclared_credential_pointer_warnings(cfg: dict) -> List[str]:
    """Warn when an auto_unlock credential var is not declared in config.

    Without the explicit field, Hermes does not know the var holds a secret
    and passes it to every spawned child process.
    """
    cfg = cfg if isinstance(cfg, dict) else {}
    missing = [
        f"{key} ({default})"
        for key, default in _CREDENTIAL_POINTER_KEYS
        if not str(cfg.get(key) or "").strip()
    ]
    if not missing:
        return []
    return [
        "auto_unlock: secrets.vaultwarden." + ", ".join(missing)
        + " not set in config.yaml, so Hermes cannot strip the credential "
        "from spawned child processes.  Re-run `hermes vaultwarden setup "
        "--auto-unlock` or add the field(s) explicitly."
    ]


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
    # Declaring the bootstrap credential lets Hermes treat BW_SESSION as the
    # one token that unlocks every other secret: it is stripped from every
    # spawned child (terminal tool, subprocesses) and can't be overwritten
    # by a vault field.  bw itself still gets it via run_secret_cli's
    # extra_env.  Hermes' child-env blocklist calls token_env({}), so only
    # the default name is stripped there; a custom session_env stays
    # protected from vault overwrites but not from child inheritance.
    token_env_key = "session_env"
    default_token_env = _DEFAULT_SESSION_ENV

    def token_env(self, cfg: dict) -> str:
        candidate = super().token_env(cfg)
        return candidate if is_valid_env_name(candidate) else _DEFAULT_SESSION_ENV

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
                    "When true, authenticate with a personal API key and mint a "
                    "session in memory for the profile-isolated bw state. "
                    "session_env is ignored in this mode (a token from .env was "
                    "never issued for the isolated state). The token is never "
                    "persisted."
                ),
                "default": False,
            },
            "remint_on_auth_expired": {
                "description": "Reuse proven in-memory sessions and retry once on expiry in auto-unlock mode; false mints on every fetch",
                "default": True,
            },
            "credentials_command": {
                "description": (
                    "Auto-unlock only: non-interactive helper run via /bin/sh -c "
                    "(e.g. secret-tool lookup) printing KEY=VALUE lines for the "
                    "client ID / client secret / master password names. Fills only "
                    "names the environment lacks; values stay in memory, never in .env"
                ),
                "default": "",
            },
            "credentials_command_timeout_seconds": {
                "description": "Hard timeout for one credentials_command run",
                "default": _CRED_CMD_TIMEOUT,
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
                "description": (
                    "Vault item whose custom fields become env vars.  "
                    "${VAR} / ${env:VAR} references are expanded from the "
                    "source environment (envdir/.env/process env)."
                ),
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
            "sync_interval_seconds": {
                "description": (
                    "Skip the network `bw sync` when the CLI state synced less "
                    "than this many seconds ago; 0 syncs on every fetch"
                ),
                "default": int(_DEFAULT_SYNC_INTERVAL),
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
        env_session = str(get_source_environment().get(session_env) or "").strip()

        auto_unlock = bool(cfg.get("auto_unlock", False))
        appdata_dir: Optional[Path] = (
            _profile_bw_appdata(home_path) if auto_unlock else None
        )
        # In auto_unlock mode the env token is never used: bw reads the
        # isolated profile dir, and a leftover BW_SESSION from .env was
        # issued for a different state dir (or a previous unlock).
        session = "" if auto_unlock else env_session
        if auto_unlock and env_session:
            result.warnings.append(
                f"auto_unlock: ignoring {session_env} from the environment; "
                "a session is used or minted for the profile-isolated bw state"
            )
        gate = auto_unlock and bool(cfg.get("remint_on_auth_expired", True))
        auth_key = None
        from_cache = False
        credential_names = (
            str(cfg.get("client_id_env") or _DEFAULT_CLIENT_ID_ENV).strip(),
            str(cfg.get("client_secret_env") or _DEFAULT_CLIENT_SECRET_ENV).strip(),
            str(cfg.get("master_password_env") or _DEFAULT_MASTER_PASSWORD_ENV).strip(),
        )
        source_env = get_source_environment()
        credential_values = [str(source_env.get(name) or "") for name in credential_names]
        sensitive = credential_values + [env_session]
        if auto_unlock:
            binary0 = find_bw(cfg.get("binary_path"))
            if binary0 is None:
                result.error = (
                    "bw binary not found.  Install it from your package manager or "
                    "https://github.com/bitwarden/clients/releases"
                )
                result.error_kind = ErrorKind.BINARY_MISSING
                return result
            try:
                credentials_env, _filled = resolve_auto_unlock_credentials(
                    credential_names, source_env,
                    cfg.get("credentials_command"),
                    cfg.get("credentials_command_timeout_seconds"),
                )
            except RuntimeError as exc:
                result.error = str(exc)
                result.error_kind = (
                    ErrorKind.TIMEOUT if "timed out" in str(exc) else ErrorKind.NOT_CONFIGURED
                )
                return result
            credential_values = [credentials_env[name] for name in credential_names]
            sensitive.extend(credential_values)
            effective = [credential_values[0].strip(), credential_values[1].strip(), credential_values[2]]
            sensitive.extend(effective)
            auth_key = (str(appdata_dir.resolve()), str(Path(binary0).resolve()),
                        str(cfg.get("server_url") or "").strip().rstrip("/"),
                        *credential_names,
                        *(hashlib.sha256(value.encode()).hexdigest() for value in effective))

            def _mint():
                return mint_session(
                    binary0, home_path=home_path, client_id_env=credential_names[0],
                    client_secret_env=credential_names[1], master_password_env=credential_names[2],
                    server_url=str(cfg.get("server_url") or ""), credentials_env=credentials_env,
                )

            with _AUTH_LOCK:
                generation = _AUTH_GENERATIONS.get(auth_key[0], 0)
                session = _AUTH_SESSIONS.get(auth_key, "") if gate else ""
                expected_session = session or None
            from_cache = bool(session)
            if not session:
                try:
                    session = _mint()
                    result.warnings.append("auto_unlock: minted an in-memory session")
                except RuntimeError as exc:
                    result.error_kind = _classify_bw_error(str(exc))
                    result.error = _safe_diagnostic(str(exc), sensitive, session_env)[:500]
                    return result
            sensitive.append(session)

        if not session:
            result.error = (
                f"secrets.vaultwarden.enabled is true but {session_env} is not "
                "set. Run `hermes vaultwarden setup`, or set "
                "secrets.vaultwarden.auto_unlock=true to mint a session from "
                "a personal API key and master password."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        item_name, item_error = resolve_item_name(cfg)
        if item_error:
            result.error = item_error
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
        try:
            sync_interval = float(
                cfg.get("sync_interval_seconds", _DEFAULT_SYNC_INTERVAL)
            )
        except (TypeError, ValueError):
            sync_interval = _DEFAULT_SYNC_INTERVAL

        login_bindings, binding_warnings = resolve_login_bindings(cfg)
        result.warnings.extend(binding_warnings)
        if auto_unlock:
            result.warnings.extend(undeclared_credential_pointer_warnings(cfg))

        def _read(token, *, force_read=False):
            kwargs = dict(
                session=token, item_name=item_name, binary=binary,
                cache_ttl_seconds=ttl, home_path=home_path,
                username_env=login_bindings["username_env"],
                password_env=login_bindings["password_env"],
                notes_env=login_bindings["notes_env"], appdata_dir=appdata_dir,
                sync_interval_seconds=sync_interval,
            )
            if force_read:
                kwargs["force_read"] = True
            return fetch_vaultwarden_secrets(**kwargs)

        try:
            secrets, warnings = _read(session, force_read=gate and not from_cache)
        except RuntimeError as exc:
            kind = _classify_bw_error(str(exc))
            original = _safe_diagnostic(str(exc), sensitive, session_env)[:500]
            if gate and from_cache and kind == ErrorKind.AUTH_EXPIRED:
                with _AUTH_LOCK:
                    if _AUTH_SESSIONS.get(auth_key) == session:
                        _AUTH_SESSIONS.pop(auth_key, None)
                        expected_session = None
            if not (gate and from_cache and kind == ErrorKind.AUTH_EXPIRED):
                result.error, result.error_kind = original, kind
                return result
            try:
                session = _mint()
                sensitive.append(session)
                secrets, warnings = _read(session, force_read=True)
                result.warnings.append("remint_on_auth_expired: read retried with an in-memory session")
            except Exception as retry_exc:  # preserve original classification
                diagnostic = _safe_diagnostic(str(retry_exc), sensitive, session_env).strip()[:240]
                result.error = original + " — recovery failed: " + diagnostic
                result.error_kind = kind
                return result
        except Exception as exc:  # noqa: BLE001 — contract: never raise
            result.error = "unexpected error: " + _safe_diagnostic(str(exc), sensitive, session_env)[:500]
            result.error_kind = ErrorKind.INTERNAL
            return result

        if gate:
            with _AUTH_LOCK:
                if (not _AUTH_RESETTING.get(auth_key[0])
                        and _AUTH_GENERATIONS.get(auth_key[0], 0) == generation
                        and _AUTH_SESSIONS.get(auth_key) == expected_session):
                    _AUTH_SESSIONS[auth_key] = session
        warnings = [_safe_diagnostic(w, sensitive, session_env, generic=False) for w in warnings]

        result.secrets = secrets
        result.warnings.extend(warnings)
        return result


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------


def _reset_cache_for_tests(home_path: Optional[Path] = None) -> None:
    _CACHE.clear()
    with _AUTH_LOCK:
        for profile in {key[0] for key in _AUTH_SESSIONS} | set(_AUTH_GENERATIONS):
            _AUTH_GENERATIONS[profile] = _AUTH_GENERATIONS.get(profile, 0) + 1
        _AUTH_SESSIONS.clear()
    _DISK_CACHE.clear(home_path)
