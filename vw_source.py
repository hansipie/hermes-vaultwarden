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
* The session token is stored in ``~/.hermes/.env`` as ``BW_SESSION``
  (or the name chosen in ``secrets.vaultwarden.session_env``).  Obtain it
  with ``export BW_SESSION=$(bw unlock --raw)`` after logging in.
* **Self-heal:** Vaultwarden allows a single live session per user, so any
  other ``bw unlock``/``login`` (vault maintenance, a fallback helper, a
  stray CLI call) silently invalidates the stored token.  When a fetch
  comes back empty / auth-dead, the source re-derives a session itself:
  read the master password from ``heal_password_file``, ensure an account
  is logged in (non-interactive API-key login via the CLI-native
  ``BW_CLIENTID``/``BW_CLIENTSECRET`` env vars when the file carries
  them), then ``bw unlock --passwordenv <var> --raw``.  The fresh token
  is written back to the ``<home>/.env`` line for ``session_env``.
  One heal attempt per process; disabled with ``self_heal: false``.
* Secrets come from a single named vault item::

      bw get item -- "<item_name>"     (BW_SESSION passed via child env)

  Every custom field whose name is a valid env-var identifier is offered
  to the orchestrator.  The item's structural ``login.username``,
  ``login.password`` and ``notes`` are *not* custom fields and are only
  exported when the user opts in via ``username_env`` / ``password_env``
  / ``notes_env`` — there's no default name to guess, so silence beats a
  wrong guess.  :meth:`VaultwardenSource.fetch` never writes
  ``os.environ`` itself.
* Caching: two-layer (in-process dict + disk JSON via the shared
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
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    is_valid_env_name,
    run_secret_cli,
    scrub_ansi,
)
from agent.secret_sources._cache import CachedFetch, DiskCache, resolve_cache_home

logger = logging.getLogger(__name__)

_BW_RUN_TIMEOUT = 30.0
_DEFAULT_SESSION_ENV = "BW_SESSION"
_DEFAULT_CACHE_TTL = 300.0

# Extra env vars the bw child process may need beyond run_secret_cli's
# base allowlist (HOME/PATH/locale).  BITWARDENCLI_APPDATA_DIR relocates
# bw's data directory; without it a user with a custom location would
# silently talk to an empty vault.
_BW_ALLOW_ENV = ("BITWARDENCLI_APPDATA_DIR",)

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


# ---------------------------------------------------------------------------
# Self-heal: re-derive a session when the stored token has been invalidated
# ---------------------------------------------------------------------------
#
# Vaultwarden allows ONE live session per user.  Any other ``bw unlock`` /
# ``bw login`` (vault maintenance, a command-source helper, a stray CLI call)
# silently invalidates the token stored in ``<home>/.env``.  Rather than fail
# with "bw returned no output" and require a hand edit, the source can
# re-derive a fresh session itself — one attempt per process, best-effort.

_DEFAULT_HEAL_PASSWORD_FILE = "~/.hermes/.env"
_DEFAULT_HEAL_PASSWORD_VAR = "BW_PASSWORD"
# CLI-native (no-underscore) names the ``bw`` CLI reads for API-key login.
_HEAL_CLIENTID_VAR = "BW_CLIENTID"
_HEAL_CLIENTSECRET_VAR = "BW_CLIENTSECRET"
# ``--raw`` emits only the token, but a token line is never the whole
# stdout in every CLI build — extract the last base64-ish line, not argv[0].
_TOKEN_LINE_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}\s*$")

# One heal attempt per process (module-level, not per call): a failed heal
# will fail again the same way, and a successful one has refreshed the env.
_HEAL_ATTEMPTED = False


def _read_keyed_file(path: Path) -> Dict[str, str]:
    """Parse a KEY=VALUE dotenv-style file (comments/blank lines skipped).

    Best-effort: unreadable/missing files yield ``{}`` — heal just falls
    back to whatever env happens to be present.
    """
    try:
        text = path.read_text()
    except OSError:
        return {}
    values: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            values[key] = value.strip().strip('"').strip("'")
    return values


def _env_file_path(home_path: Path, session_env: str) -> Path:
    return Path(home_path) / ".env"


def _update_env_file_session(home_path: Path, session_env: str, token: str) -> bool:
    """Replace the ``<session_env>=`` line in ``<home>/.env`` with *token*.

    Atomic (temp + rename), 0600.  Returns ``False`` (no write) when the
    file is absent.  Raises ``OSError`` on write failure — callers treat
    it as best-effort and keep the in-memory token regardless.
    """
    env_path = _env_file_path(home_path, session_env)
    if not env_path.is_file():
        return False
    token = token.strip()  # belt-and-braces: no trailing newline in the file
    text = env_path.read_text()
    new_line = f"{session_env}={token}"
    if re.search(rf"^{re.escape(session_env)}=.*$", text, flags=re.M):
        new_text, n = re.subn(
            rf"^{re.escape(session_env)}=.*$", new_line, text, flags=re.M
        )
        assert n == 1
    else:
        new_text = text + ("\n" if text and not text.endswith("\n") else "") + new_line + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=str(env_path.parent), prefix=".env.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(new_text)
        os.chmod(tmp_name, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp_name, env_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return True


def _is_session_error(result: Tuple[Dict[str, str], List[str]]) -> bool:
    """True when a fetch result means "dead/missing session", not "wrong item"."""
    secrets, warnings = result
    if secrets:
        return False
    for w in warnings:
        if "no custom fields" in w:
            return False  # session worked; the item just has nothing to give
    return bool(warnings) or not secrets


def _rederive_session(
    bw: Path,
    session_env: str,
    heal_password_file: Optional[str],
    heal_password_var: str,
    home_path: Optional[Path],
    extra_notes: List[str],
) -> Optional[str]:
    """Re-derive a fresh ``BW_SESSION`` token non-interactively.

    Returns the new token, or ``None`` when healing is not possible
    (password material missing, bw not logged in, unlock failed).  Never
    raises — a heal failure degrades to the original fetch result.
    """
    global _HEAL_ATTEMPTED
    if _HEAL_ATTEMPTED:
        return None
    _HEAL_ATTEMPTED = True
    try:
        extra_notes.append("stored session dead — attempting self-heal")

        pw_file = Path(os.path.expanduser(heal_password_file or _DEFAULT_HEAL_PASSWORD_FILE))
        file_values = _read_keyed_file(pw_file)
        pw_value = file_values.get(heal_password_var)
        if not pw_value:
            extra_notes.append(
                f"self-heal skipped: {heal_password_var!r} not found in {pw_file}"
            )
            return None

        # Keep the password out of argv and of /proc/<pid>/cmdline: the
        # unlock child reads it from its own env via --passwordenv.  A
        # 0600 temp file is the fallback when the value must stay on disk.
        unlock_env: Dict[str, str] = {}
        if " " not in pw_value:
            unlock_env[heal_password_var] = pw_value

        # API-key login (CLI-native no-underscore vars, non-interactive,
        # also recovers from a full logout) — only when the file carries
        # the key pair.  Some CLI builds' apikey logins leave the session
        # locked, so always follow with the master-password unlock below.
        client_id = file_values.get("BW_CLIENT_ID")
        client_secret = file_values.get("BW_CLIENT_SECRET")
        if client_id and client_secret:
            login_env: Dict[str, str] = {
                _HEAL_CLIENTID_VAR: client_id,
                _HEAL_CLIENTSECRET_VAR: client_secret,
                "NODE_OPTIONS": "--no-deprecation",
            }
            # Some CLI builds honor BW_SERVER_URL from the environment;
            # others resolve the server from persistent state.  Passing it
            # through costs nothing and makes the credentials file the
            # single source of truth where it is honored.
            if file_values.get("BW_SERVER_URL"):
                login_env["BW_SERVER_URL"] = file_values["BW_SERVER_URL"]
            run_secret_cli(
                [str(bw), "login", "--apikey", "--raw"],
                extra_env=login_env,
                timeout=_BW_RUN_TIMEOUT,
            )

        unlock_argv = [str(bw), "unlock", "--passwordenv", heal_password_var, "--raw"]
        if not unlock_env:
            fd, pw_file_tmp = tempfile.mkstemp(prefix="bw-pw.")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(pw_value)
                os.chmod(pw_file_tmp, stat.S_IRUSR | stat.S_IWUSR)
                unlock_argv = [str(bw), "unlock", "--passwordfile", pw_file_tmp, "--raw"]
            except BaseException:
                try:
                    os.unlink(pw_file_tmp)
                except OSError:
                    pass
                raise
        else:
            pw_file_tmp = None
        try:
            proc = run_secret_cli(
                unlock_argv,
                extra_env=unlock_env,
                timeout=_BW_RUN_TIMEOUT,
            )
        finally:
            if pw_file_tmp:
                try:
                    os.unlink(pw_file_tmp)
                except OSError:
                    pass

        raw = proc.stdout or ""
        token = ""
        for line in reversed(raw.splitlines()):
            if _TOKEN_LINE_RE.match(line.strip()):
                token = line.strip()  # strip(): --raw output ends in \n
                break
        if not token:
            err = scrub_ansi((proc.stderr or "")).strip()
            extra_notes.append(
                f"self-heal failed: bw unlock rc={proc.returncode} "
                f"no token in output ({err[:120] or 'no stderr'})"
            )
            return None

        if home_path is not None:
            try:
                wrote = _update_env_file_session(Path(home_path), session_env, token)
                if wrote:
                    extra_notes.append(f"self-heal ok — refreshed {session_env} in .env")
                else:
                    extra_notes.append(
                        f"self-heal ok — no .env at {home_path} to refresh "
                        "(in-memory only)"
                    )
            except OSError as exc:
                extra_notes.append(f"self-heal ok, but .env write-back failed: {exc}")
        else:
            extra_notes.append("self-heal ok (in-memory only)")
        return token
    except Exception as exc:  # noqa: BLE001 — heal must never mask the fetch
        extra_notes.append(f"self-heal failed: {exc}")
        return None


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
    self_heal: bool = False,
    session_env: str = _DEFAULT_SESSION_ENV,
    heal_password_file: Optional[str] = None,
    heal_password_var: str = _DEFAULT_HEAL_PASSWORD_VAR,
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
    )

    # Self-heal: a dead session surfaces as empty output, not an error.
    # Re-derive a token and retry once (never cached under the old token).
    heal_notes: List[str] = []
    if self_heal and _is_session_error((secrets, warnings)):
        healed = _rederive_session(
            bw,
            session_env,
            heal_password_file,
            heal_password_var,
            home_path,
            heal_notes,
        )
        if healed and healed != session:
            session = healed
            retry_secrets, retry_warnings = _run_bw_get_item(
                bw,
                session,
                item_name,
                username_env=username_env,
                password_env=password_env,
                notes_env=notes_env,
            )
            secrets, warnings = retry_secrets, retry_warnings

    # Heal notes (skipped/failed/ok + refresh status) are surfaced
    # alongside the (possibly retried) result; a successful retry drops
    # the stale dead-session marker from the first pass.
    if heal_notes:
        warnings = heal_notes

    # A dead session that the heal could not fix must not be cached: an
    # empty result would otherwise mask the heal attempt for the whole
    # TTL window, even if the session recovers meanwhile.
    if not secrets and _is_session_error((secrets, warnings)):
        return secrets, warnings

    import time as _time

    # Cache under the session that actually served the result — a healed
    # fetch must not be filed (or re-served) under the dead token's key.
    cache_key = (
        cache_key[0],
        _session_fingerprint(session),
        *cache_key[2:],
    )
    entry = CachedFetch(secrets=secrets, fetched_at=_time.time())
    _CACHE[cache_key] = entry
    if use_cache:
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
) -> Tuple[Dict[str, str], List[str]]:
    # Session travels via the child env (bw reads BW_SESSION natively)
    # instead of a --session argv flag, keeping the token out of
    # /proc/<pid>/cmdline.  The item name follows a `--` terminator so a
    # user-named item like "--raw" can never parse as a flag.
    # NODE_OPTIONS keeps Node deprecation noise off stdout/stderr so the
    # JSON parsing (and the heal's token extraction) never trip on it.
    proc = run_secret_cli(
        [str(bw), "get", "item", "--", item_name],
        allow_env=_BW_ALLOW_ENV,
        extra_env={"BW_SESSION": session, "NODE_OPTIONS": "--no-deprecation"},
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
    if "timed out" in lowered:
        return ErrorKind.TIMEOUT
    if "failed to invoke" in lowered or "binary not found" in lowered:
        return ErrorKind.BINARY_MISSING
    if any(tok in lowered for tok in (
        "session", "unlock", "not logged in", "vault is locked", "locked",
        "unauthorized", "invalid master password", "mac failed",
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
        session_env = _DEFAULT_SESSION_ENV
        if isinstance(cfg, dict):
            candidate = str(cfg.get("session_env") or session_env)
            if is_valid_env_name(candidate):
                session_env = candidate
        return frozenset({session_env})

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Master switch", "default": False},
            "session_env": {
                "description": "Env var holding the `bw unlock --raw` session token",
                "default": _DEFAULT_SESSION_ENV,
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
            "self_heal": {
                "description": (
                    "Re-derive the session non-interactively when the stored "
                    "token has been invalidated (Vaultwarden allows one live "
                    "session per user).  Defaults to true."
                ),
                "default": True,
            },
            "heal_password_file": {
                "description": (
                    "KEY=VALUE file holding the heal credentials "
                    "(master-password var, plus optional BW_CLIENT_ID / "
                    "BW_CLIENT_SECRET for non-interactive apikey login). "
                    f"Default: {_DEFAULT_HEAL_PASSWORD_FILE}"
                ),
                "default": _DEFAULT_HEAL_PASSWORD_FILE,
            },
            "heal_password_var": {
                "description": (
                    "Key in heal_password_file holding the master password "
                    "(passed to `bw unlock` via --passwordenv, never argv)."
                ),
                "default": _DEFAULT_HEAL_PASSWORD_VAR,
            },
        }

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}

        session_env = str(cfg.get("session_env") or _DEFAULT_SESSION_ENV)
        session = os.environ.get(session_env, "").strip()
        if not session:
            result.error = (
                f"secrets.vaultwarden.enabled is true but {session_env} is not "
                "set.  Run `bw unlock --raw` and store the output in your .env "
                f"file as {session_env}=<token>, or run "
                "`hermes vaultwarden setup`."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        item_name = str(cfg.get("item_name") or "").strip()
        if not item_name:
            result.error = (
                "secrets.vaultwarden.item_name is empty.  "
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
                self_heal=bool(cfg.get("self_heal", True)),
                session_env=session_env,
                heal_password_file=str(cfg.get("heal_password_file") or "").strip() or None,
                heal_password_var=str(
                    cfg.get("heal_password_var") or _DEFAULT_HEAL_PASSWORD_VAR
                ).strip() or _DEFAULT_HEAL_PASSWORD_VAR,
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
