# pfhop

A small, self-hosted web panel for a **Postfix relay server**. It shows Postfix and
server health and the mail queue, and backs up the configuration. Later phases add
live queue tracking, weekly reports and configuration editing.

Built for Rocky Linux / RHEL 9–10. It runs natively with Python, systemd and nginx.
There is no Docker and no build step.

## Features (current: phase 1)

- **Dashboard** (auto-refresh): Postfix service state and uptime, queue counters
  (active / deferred / hold), oldest message, top deferral reasons, relay settings,
  server info (OS, kernel, CPU, load, RAM, swap, disks, queue-disk free space vs `queue_minfree`)
- **Postfix configuration** (read-only): `postconf -n` with defaults and descriptions, `master.cf`
- **Backups** (manual):
  - Postfix configuration → `.tar.gz` (config directory + `postconf -n/-M/-P` output)
  - pfhop settings and users → `.json`
- **Users**: local accounts, roles `admin` / `viewer`, scrypt password hashes
- **Audit log**: who did what, when, from which IP (can be switched off in Settings)
- **Settings**: thresholds, refresh interval, instance name

## Roadmap

1. ✅ Skeleton, login, dashboard, read-only config, backups
2. Log collector + **live queue** page (queued → completed with sent / bounced / expired)
3. Reports + weekly e-mail report (recipients / sender configured in the UI)
4. Queue actions (flush, hold, release, delete) + Postfix start / stop / reload
5. Editing Postfix settings and relays, with automatic backup and rollback
6. Packaging polish

## Security model

- The app runs as the unprivileged `pfhop` user and listens on `127.0.0.1:8000` only.
- nginx terminates TLS and allows only the networks in `/etc/nginx/pfhop-allow.conf`.
- Root actions go through **one** whitelisted program, `/usr/libexec/pfhop/pfhop-helper`.
  Sudo allows only this program, and the helper validates every sub-command.
- CSRF tokens on every form, `SameSite=Strict` secure cookies, strict CSP, login throttling.

## Install

```bash
git clone https://github.com/axzeLx/pfhop.git /srv/pfhop
cd /srv/pfhop
sudo ./install.sh --server-name pfhop.example.com
sudo pfhop useradd admin --role admin
```

The installer is idempotent. It only installs missing packages and never upgrades
existing ones. It creates:

| Path | Purpose |
|---|---|
| `/etc/pfhop/pfhop.conf` | static config (random `secret_key` generated) |
| `/etc/pfhop/tls/` | self-signed certificate (replace with your own if you like) |
| `/var/lib/pfhop/` | SQLite database and backups |
| `/etc/nginx/conf.d/pfhop.conf`, `/etc/nginx/pfhop-allow.conf` | reverse proxy and allow-list |
| `/etc/systemd/system/pfhop.service` | service |
| `/usr/libexec/pfhop/pfhop-helper`, `/etc/sudoers.d/pfhop` | root helper |
| `/usr/local/bin/pfhop` | CLI (`useradd`, `passwd`, `users`) |

By default the allow-list is copied from Postfix `mynetworks`. Use `--allow "10.0.0.0/8 …"` to override it.

## CLI

```bash
pfhop users                          # list accounts
pfhop useradd alice --role viewer    # create account (asks for password)
pfhop passwd alice                   # reset password
```

## Development

```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp pfhop.conf.example dev.conf   # set secret_key, cookie_secure=false, data_dir, use_sudo=false
PFHOP_CONFIG=dev.conf ./venv/bin/python -m pfhop useradd dev --role admin
PFHOP_CONFIG=dev.conf ./venv/bin/python -m pfhop serve --port 8011
```

## License

MIT. See [LICENSE](LICENSE).
