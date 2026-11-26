# FAQ

## What does "unattended mode" mean?

Unattended mode lets the plugin authenticate on its own, with nobody there to
type a password or paste a session token. Turn it on with
`hermes vaultwarden setup --auto-unlock`.

At Hermes startup the plugin:

1. Reads `BW_CLIENTID`, `BW_CLIENTSECRET` and `BW_MASTER_PASSWORD` from the
   environment.
2. Runs `bw login --apikey`, only if the CLI is not already logged in.
3. Runs `bw unlock --passwordenv … --raw` to get a session token.
4. Keeps that token **in memory only**. It is never written to `.env` or
   `config.yaml`.

It is meant for services that run with nobody at the keyboard: a systemd unit,
a container, a server that reboots by itself. After a reboot the service comes
back up and gets its secrets with no one stepping in.

| | Unattended (`--auto-unlock`) | Interactive |
|---|---|---|
| Login | automatic, with the personal API key | you, with `bw login` |
| Unlock | automatic, with the master password from the environment | you, with `bw unlock` |
| `BW_SESSION` token | in memory only (an existing `BW_SESSION` is ignored) | stored in the Hermes `.env` |
| CLI state | isolated per Hermes profile | default `bw` state |
| Server | explicit HTTPS URL required | whatever `bw config server` set |

The trade-off is that the master password has to reach the process. Inject it
with your service manager's secret facility (for example systemd
`LoadCredential=`). Never put it in a unit file or in `config.yaml`. See
[Setup modes](README.md#setup-modes) for details.

## Do I have to supply the environment variables every time I start Hermes?

Yes. In unattended mode, the plugin reads `BW_CLIENTID`, `BW_CLIENTSECRET` and
`BW_MASTER_PASSWORD` from the environment at **every** startup and
deliberately stores them nowhere. If `hermes vaultwarden status` shows them as
`missing`, the plugin cannot log in. A `BW_SESSION` already in your shell is
ignored in this mode, because the plugin mints its own session.

You don't have to type them each time: have something inject them at launch.
From most to least secure:

**1. The OS keyring (recommended on a workstation).** Store the secrets once
in GNOME Keyring or KWallet, which unlocks when you log in:

```bash
secret-tool store --label="BW client id"     service hermes-bw key BW_CLIENTID
secret-tool store --label="BW client secret" service hermes-bw key BW_CLIENTSECRET
secret-tool store --label="BW master pw"     service hermes-bw key BW_MASTER_PASSWORD
```

Then wrap `hermes` in a shell function, for example in `~/.bashrc`:

```bash
hermes() {
  BW_CLIENTID="$(secret-tool lookup service hermes-bw key BW_CLIENTID)" \
  BW_CLIENTSECRET="$(secret-tool lookup service hermes-bw key BW_CLIENTSECRET)" \
  BW_MASTER_PASSWORD="$(secret-tool lookup service hermes-bw key BW_MASTER_PASSWORD)" \
  command hermes "$@"
}
```

The variables exist only for the `hermes` process. Nothing is written to disk
in clear text, and they stay out of your shell's environment.

**2. A systemd service (gateway, start at boot).** Use
`LoadCredentialEncrypted=` with `systemd-creds encrypt` rather than
`Environment=` in the unit file.

**3. The Hermes `.env` (works, but not recommended).** The plugin also reads
the Hermes `.env`, so the three variables can go there. The master password
then sits on disk in clear text, which defeats the purpose of using
Vaultwarden.

**Alternative: interactive mode.** If you don't need unattended startup,
unlock once and let setup store the session token in the Hermes `.env`:

```bash
hermes vaultwarden setup --session "$(bw unlock --raw)"
```

The token stays valid until the session expires or you run `bw lock` /
`bw logout`.

## `bw login --apikey` fails with "Invalid API Key; Organization API Key currently not supported"

`BW_CLIENTID` holds an **organization** API key. `bw login --apikey`, and this
plugin's unattended mode, accept only a **personal** API key.

Check the prefix of the client ID:

| `BW_CLIENTID` prefix | Key type | Accepted |
|---|---|---|
| `user.…` | Personal API key | Yes |
| `organization.…` | Organization API key | No (this error) |

To get the personal key in the Vaultwarden web vault:

1. Open your profile and go to **Account settings → Security → Keys**.
2. Click **View API Key** and confirm with your master password.
3. Copy `client_id` (it starts with `user.`) and `client_secret`.

Do not use the key under *Organization → Settings → API Key*.

Then log in again:

```bash
export BW_CLIENTID='user.…'
export BW_CLIENTSECRET='…'
bw logout 2>/dev/null; bw login --apikey
bw unlock --passwordenv BW_MASTER_PASSWORD   # the API key logs in, it does not unlock
```

Items shared through the organization stay readable with the personal key, as
long as your account is a member of that organization.

If the client ID already starts with `user.` and the error persists, compare
`bw --version` with your Vaultwarden server version: the CLI and the server
may be incompatible.
