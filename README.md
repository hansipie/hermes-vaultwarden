# hermes-vaultwarden

Hermes Agent plugin: pull env vars from a **Vaultwarden** (or Bitwarden
Password Manager) vault item's custom fields at process startup, via the
`bw` CLI.

Vaultwarden implements the Bitwarden *Password Manager* API — not
*Secrets Manager* — so Hermes' bundled `secrets.bitwarden` source (which
uses the `bws` CLI) does not work with self-hosted Vaultwarden
instances.  This plugin bridges that gap as an external
[`SecretSource`](https://github.com/NousResearch/hermes-agent) plugin
(successor to in-tree PR
[#42300](https://github.com/NousResearch/hermes-agent/pull/42300),
reworked for the pluggable interface introduced in
[#59498](https://github.com/NousResearch/hermes-agent/pull/59498)).

## Install

```bash
git clone https://github.com/hansipie/hermes-vaultwarden ~/Code/hermes-vaultwarden
ln -s ~/Code/hermes-vaultwarden ~/.hermes/plugins/vaultwarden
```

User plugins are **opt-in** — add the plugin to `plugins.enabled` in
`~/.hermes/config.yaml` (the setup wizard does this for you):

```yaml
plugins:
  enabled:
    - vaultwarden
```

Install the `bw` CLI (not auto-installed): `npm install -g @bitwarden/cli`,
snap, or the native binary from https://bitwarden.com/help/cli/.

## Setup

```bash
bw config server https://your-vaultwarden.example.com
bw login
export BW_SESSION=$(bw unlock --raw)
hermes vaultwarden setup
```

The wizard verifies `bw`, stores the session token in `~/.hermes/.env`,
lets you pick the vault item, optionally maps `login.username` /
`login.password` / `notes` to env vars, test-fetches it, and enables
everything.

Secrets are read from **one vault item's custom fields** — name each
field after the env var it should set (e.g. `OPENROUTER_API_KEY`).
The item's structural `login.username` / `login.password` / `notes`
are not custom fields and are ignored unless you opt in — either
answer the wizard's prompts (blank = skip) or pass
`--username-env` / `--password-env` / `--notes-env` for non-interactive
runs (see Config below). Re-running `setup` and leaving a binding blank
clears it from `config.yaml`.

## Commands

| Command | What it does |
|---|---|
| `hermes vaultwarden setup` | Interactive wizard (flags: `--session`, `--item-name`, `--server-url`, `--username-env`, `--password-env`, `--notes-env` for non-TTY) |
| `hermes vaultwarden status` | Config, binary, server, session presence |
| `hermes vaultwarden sync` | `bw sync` + fresh fetch, dry-run table; `--apply` exports into the current process |
| `hermes vaultwarden disable` | Flips `secrets.vaultwarden.enabled` to false and clears the disk cache |

## Config (`secrets.vaultwarden.*` in config.yaml)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `session_env` | `BW_SESSION` | Env var holding the `bw unlock --raw` token |
| `item_name` | — | Vault item whose custom fields become env vars |
| `username_env` | — | Env var for `login.username`; unset = not exported |
| `password_env` | — | Env var for `login.password`; unset = not exported |
| `notes_env` | — | Env var for the item's `notes`; unset = not exported |
| `override_existing` | `false` | Overwrite vars already set by `.env`/shell (never another secret source) |
| `cache_ttl_seconds` | `300` | TTL for both cache layers; `0` disables caching entirely |
| `binary_path` | — | Pin an exact `bw` binary path |
| `timeout_seconds` | `120` | Orchestrator wall-clock budget around the fetch |
| `self_heal` | `true` | Re-derive the session non-interactively when the stored token is dead |
| `heal_password_file` | `~/.hermes/.env` | KEY=VALUE file with the heal credentials (password var, optional `BW_CLIENT_ID`/`BW_CLIENT_SECRET`/`BW_SERVER_URL`) |
| `heal_password_var` | `BW_PASSWORD` | Key in `heal_password_file` holding the master password |

Config keys are identical to the old in-tree PR #42300 branch — an
existing config keeps working unchanged.

## Behaviour & caveats

- **Bulk source**: all custom fields of the item are offered implicitly.
  Explicit mapped bindings (e.g. 1Password `env:` entries) outrank them
  on contested vars; conflicts are warned, never silently clobbered.
- **Login/notes bindings**: `username_env`/`password_env`/`notes_env`
  are opt-in — there's no default name to guess a structural field
  into, so unset means not exported. If a binding's target name also
  matches a custom field, the login/notes value wins and a warning is
  emitted.
- **Self-heal**: Vaultwarden allows ONE live session per user, so any other
  `bw unlock`/`login` (vault maintenance, a command-source helper, a stray
  CLI call) silently invalidates the stored token and the next fetch comes
  back empty ("bw returned no output"). With `self_heal: true` (default)
  the source recovers on its own: it reads the master password from
  `heal_password_file` (default `~/.hermes/.env` — the same file the
  session token lives in, so one file holds the only secrets the plugin
  needs), does a non-interactive API-key login when the file carries the
  client-id/secret pair (CLI-native `BW_CLIENTID`/`BW_CLIENTSECRET`
  env vars, `NODE_OPTIONS=--no-deprecation` to keep stdout clean, and
  `BW_SERVER_URL` passed through when present), then
  `bw unlock --passwordenv <var> --raw` — the password never touches argv.
  The fresh token is written back to the `.env` line for `session_env`
  (atomic, 0600), so the stored token stays warm for other readers. One
  heal attempt per process; a heal failure degrades to the original empty
  result (uncached, so it isn't masked by the TTL), and the whole heal is
  best-effort — it never raises. Set `self_heal: false` to restore the
  old "fail and print a warning" behaviour.
- The session token env var is **protected** — a vault field named
  `BW_SESSION` can never overwrite the credential used to reach the vault.
- **Timing**: plugin secret sources are discovered *after* the very
  first env load of the process that discovers them.  They apply to every
  Hermes process spawned afterwards (gateway children, cron sessions,
  subagents).  For secrets the first interactive process itself needs,
  use `hermes vaultwarden sync --apply` or keep them in `.env`.
- Failures (missing binary, expired session, unknown item) never block
  startup — they surface as one-line warnings with a machine-readable
  error kind.
- Cache: in-process dict + `~/.hermes/cache/vaultwarden_cache.json`
  (atomic writes, mode `0600`, keyed on a session fingerprint — the
  token itself is never written).  A stale `bw_cache.json` from the old
  in-tree branch is dead weight and safe to delete.

## Tests

```bash
HERMES_AGENT_SRC=~/Code/hermes-agent \
  uv run --with pytest --with rich --with pyyaml pytest tests/ -v
```

`HERMES_AGENT_SRC` must point at a hermes-agent checkout that includes
the `SecretSource` interface (post-#59498).  The suite is hermetic (no
real vault, subprocess mocked) and includes the upstream
`SecretSourceConformance` kit.
