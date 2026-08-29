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

Clone the repository, then symlink or copy it to
`$HERMES_HOME/plugins/vaultwarden`.

User plugins are **opt-in** — add the plugin to `plugins.enabled` in
`~/.hermes/config.yaml` (the setup wizard does this for you):

```yaml
plugins:
  enabled:
    - vaultwarden
```

Install the `bw` CLI (not auto-installed): `npm install -g @bitwarden/cli`,
snap, or the native binary from https://bitwarden.com/help/cli/.

## Setup modes

### Unattended services (recommended)

Create a **personal API key** for the dedicated Bitwarden/Vaultwarden account.
This is not a Bitwarden Secrets Manager organization access token. Supply the
three bootstrap values to the Hermes process without writing them to
`config.yaml`:

```bash
export BW_CLIENTID='user.…'
export BW_CLIENTSECRET='…'
export BW_MASTER_PASSWORD='…'
hermes vaultwarden setup --auto-unlock \
  --server-url https://your-vaultwarden.example.com \
  --item-id '<vault-item-uuid>'
```

At startup the plugin checks the CLI state, logs in with `bw login --apikey`
only when unauthenticated, and unlocks with `bw unlock --passwordenv … --raw`.
The session token remains in process memory. Each Hermes profile gets isolated
CLI state under `$HERMES_HOME/plugin-data/vaultwarden/bw-cli`, so profiles do
not share login state.

Unattended mode requires an explicit HTTPS `server_url` and verifies that the
CLI persisted it before sending credentials. Sandboxed wrappers that cannot
write the profile directory therefore fail closed; use Bitwarden's standalone
CLI artifact or grant the wrapper access to `$HERMES_HOME`.
Use `--binary-path /absolute/path/to/bw` to pin the standalone CLI when a
desktop package also exposes a sandboxed `bw` wrapper on `PATH`.

For system services, inject the three bootstrap variables with your service
manager's secret/credential facility. Do not put values in unit files or
`config.yaml`.

If the Vaultwarden endpoint uses a private CA, set `NODE_EXTRA_CA_CERTS` to its
PEM certificate path. The plugin passes only that standard trust-path variable
to `bw`; it never disables TLS verification.

### Interactive session

Existing interactive behavior remains supported:

```bash
bw config server https://your-vaultwarden.example.com
bw login
export BW_SESSION=$(bw unlock --raw)
hermes vaultwarden setup --item-id '<vault-item-uuid>'
```

The setup command reads `BW_SESSION` from its environment but never accepts a
session on the command line and never persists it.

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
| `hermes vaultwarden setup` | Configure authentication and select an item; `--item-id` is preferred |
| `hermes vaultwarden status` | Config, binary, server, and bootstrap-variable presence (never values) |
| `hermes vaultwarden sync` | `bw sync` + fresh orchestrated fetch, dry-run table; `--apply` commits only Vaultwarden-attributed values to the current process |
| `hermes vaultwarden reset-auth` | Log out only this Hermes profile's isolated `bw` state |
| `hermes vaultwarden disable` | Flips `secrets.vaultwarden.enabled` to false and clears the disk cache |

## Config (`secrets.vaultwarden.*` in config.yaml)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `session_env` | `BW_SESSION` | Env var holding the `bw unlock --raw` token |
| `auto_unlock` | `false` | Mint a memory-only session from personal API-key credentials |
| `client_id_env` | `BW_CLIENTID` | Name of the personal API-key client-ID env var |
| `client_secret_env` | `BW_CLIENTSECRET` | Name of the personal API-key client-secret env var |
| `master_password_env` | `BW_MASTER_PASSWORD` | Name of the master-password env var |
| `server_url` | — | Vaultwarden URL used by this profile's isolated CLI state |
| `item_id` | — | Immutable vault item UUID (preferred) |
| `item_name` | — | Vault item whose custom fields become env vars |
| `username_env` | — | Env var for `login.username`; unset = not exported |
| `password_env` | — | Env var for `login.password`; unset = not exported |
| `notes_env` | — | Env var for the item's `notes`; unset = not exported |
| `override_existing` | `false` | Overwrite vars already set by `.env`/shell (never another secret source) |
| `cache_ttl_seconds` | `0` | Plaintext cache TTL; disabled by default |
| `binary_path` | — | Pin an exact `bw` binary path |
| `timeout_seconds` | `120` | Orchestrator wall-clock budget around the fetch |

Existing `BW_SESSION` + `item_name` configurations remain supported. Re-run
setup to migrate to unattended authentication and immutable `item_id` lookup.

## Behaviour & caveats

- **Bulk source**: all custom fields of the item are offered implicitly.
  Explicit mapped bindings (e.g. 1Password `env:` entries) outrank them
  on contested vars; conflicts are warned, never silently clobbered.
- **Login/notes bindings**: `username_env`/`password_env`/`notes_env`
  are opt-in — there's no default name to guess a structural field
  into, so unset means not exported. If a binding's target name also
  matches a custom field, the login/notes value wins and a warning is
  emitted.
- Bootstrap variables are **protected** — vault fields cannot overwrite the
  session, API-key, or master-password variables used to reach the vault.
- Empty custom-field values are skipped with a warning, so an empty vault
  field cannot erase a working credential even when overrides are enabled.
- Item names and IDs beginning with `-` are rejected because current `bw`
  treats them as options and rejects the usual `--` option terminator.
- Current Hermes re-runs secret-source loading after plugin discovery, so a
  newly discovered plugin can contribute secrets to the same invocation.
- On every cache miss, the plugin runs native `bw sync` before `bw get item`.
  A failed sync fails the source fetch rather than applying stale local-vault
  data. A positive plaintext cache TTL intentionally defers both operations
  until that cache entry expires; the default TTL is zero.
- Failures (missing binary, expired session, unknown item) never block
  startup — they surface as one-line warnings with a machine-readable
  error kind.
- Plaintext caching is disabled by default. Setting a positive TTL enables an
  in-process cache plus `$HERMES_HOME/cache/vaultwarden_cache.json` (atomic
  mode `0600`, keyed on a session fingerprint; the token itself is not
  written).

## License status

The upstream repository currently declares no license. That means the code is
source-visible but does not presently grant general permission to copy,
modify, or redistribute it. Contributors and adopters should ask the upstream
maintainer to add an explicit license.

## Tests

```bash
HERMES_AGENT_SRC=~/Code/hermes-agent \
  uv run --with pytest --with rich --with pyyaml pytest tests/ -v
```

`HERMES_AGENT_SRC` must point at a hermes-agent checkout that includes
the `SecretSource` interface (post-#59498).  The suite is hermetic (no
real vault, subprocess mocked) and includes the upstream
`SecretSourceConformance` kit.
