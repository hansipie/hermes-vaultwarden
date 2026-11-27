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
This is not a Bitwarden Secrets Manager organization access token (see the
[FAQ](FAQ.md) if `bw login --apikey` rejects it). Supply the
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
The session token remains in process memory; any `BW_SESSION` already present
in the environment is ignored in this mode (with a warning), since it was not
issued for the isolated CLI state. Each Hermes profile gets isolated
CLI state under `$HERMES_HOME/plugin-data/vaultwarden/bw-cli`, so profiles do
not share login state. Within one process, a session is reused only after a
successful vault read. If a cached session expires, the plugin mints once and
retries the read once (a logged-out CLI state is not retried). Sessions are
never persisted for reuse across processes.
Set `remint_on_auth_expired: false` to disable both reuse and recovery; auto
mode then mints on every fetch. Session mode is unaffected.

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

The setup command takes the token from `--session`, then `BW_SESSION`, and
otherwise prompts for it (hidden input). In this mode the token is stored in
the Hermes `.env` so the gateway and later processes can use it, and
`override_existing` defaults to `true` (vault values win over `.env`), as
before auto-unlock existed. `bw` honours a relocated `BITWARDENCLI_APPDATA_DIR`
in this mode.

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
| `auto_unlock` | `false` | Mint a memory-only session from personal API-key credentials (`session_env` is then ignored) |
| `remint_on_auth_expired` | `true` | Reuse proven in-memory auto-unlock sessions and retry once after expiry |
| `client_id_env` | `BW_CLIENTID` | Name of the personal API-key client-ID env var |
| `client_secret_env` | `BW_CLIENTSECRET` | Name of the personal API-key client-secret env var |
| `master_password_env` | `BW_MASTER_PASSWORD` | Name of the master-password env var |
| `server_url` | — | Vaultwarden URL used by this profile's isolated CLI state |
| `item_id` | — | Immutable vault item UUID (preferred; wins over `item_name`) |
| `item_name` | — | Vault item whose custom fields become env vars; `setup` stores only one of the two. Both accept `${VAR}` / `${env:VAR}` refs, resolved from the Hermes environment |
| `username_env` | — | Env var for `login.username`; unset = not exported |
| `password_env` | — | Env var for `login.password`; unset = not exported |
| `notes_env` | — | Env var for the item's `notes`; unset = not exported |
| `override_existing` | `false` (setup writes `true` in session mode) | Overwrite vars already set by `.env`/shell (never another secret source) |
| `sync_interval_seconds` | `300` | Skip the network `bw sync` when the CLI state synced less than this ago; `0` syncs on every fetch |
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
- **Child processes**: Hermes strips `BW_SESSION` from every spawned child
  (terminal tool, subprocesses). It strips `BW_CLIENTSECRET` and
  `BW_MASTER_PASSWORD` too, because `setup --auto-unlock` writes
  `client_secret_env` / `master_password_env` into `config.yaml` (Hermes
  withholds any var a `*_secret_env` / `*_password_env` field names). If
  those fields are missing, `fetch` and `status` warn. `BW_CLIENTID` is an
  identifier, not a secret, and is not stripped.
- The master password is passed to `bw unlock --passwordenv` verbatim;
  leading or trailing spaces are kept.
- Empty custom-field values are skipped with a warning, so an empty vault
  field cannot erase a working credential even when overrides are enabled.
- Item names and IDs beginning with `-` are rejected because current `bw`
  treats them as options and rejects the usual `--` option terminator.
- Current Hermes re-runs secret-source loading after plugin discovery, so a
  newly discovered plugin can contribute secrets to the same invocation.
- On a cache miss, the plugin runs native `bw sync` before `bw get item`,
  unless the CLI state synced less than `sync_interval_seconds` ago (300 s by
  default, read locally from `bw status`). A repeated startup or the
  post-discovery reload therefore skips the network round-trip, and local
  data is never older than that interval. A failed sync fails the source
  fetch rather than applying stale local-vault data, so a host that has been
  offline for longer than the interval still fails closed. Set `0` to sync on
  every fetch. A positive plaintext cache TTL defers both operations until
  that cache entry expires; the default TTL is zero.
- Failures (missing binary, expired session, unknown item) never block
  startup — they surface as one-line warnings with a machine-readable
  error kind.
- Plaintext caching is disabled by default. Setting a positive TTL enables an
  in-process cache plus `$HERMES_HOME/cache/vaultwarden_cache.json` (atomic
  mode `0600`, keyed on a session fingerprint; the token itself is not
  written).

## Tests

```bash
HERMES_AGENT_SRC=~/Code/hermes-agent \
  uv run --with pytest --with rich --with pyyaml pytest tests/ -v
```

`HERMES_AGENT_SRC` must point at a hermes-agent checkout that includes
the `SecretSource` interface (post-#59498).  The suite is hermetic (no
real vault, subprocess mocked) and includes the upstream
`SecretSourceConformance` kit.
