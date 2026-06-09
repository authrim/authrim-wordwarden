# systemd Deployment

This guide installs Authrim Wordwarden as a Linux systemd service. It assumes
Wordwarden runs near LDAP/AD and either binds to localhost behind a tunnel/reverse
proxy or terminates HTTPS itself.

## Files

Recommended layout:

```text
/usr/local/bin/wordwarden
/etc/authrim-wordwarden/config.yaml
/etc/authrim-wordwarden/wordwarden.env
/etc/authrim-wordwarden/ca/ldap-ca.pem
/etc/systemd/system/authrim-wordwarden.service
```

Keep `config.yaml`, CA files, and env files readable by the `wordwarden` user.
Do not put raw passwords or HMAC secrets directly in `config.yaml`; use `env:` or
`file:` secret refs.

The sample `wordwarden.env` is sourced by `/bin/sh` in the diagnostic examples,
so keep it in simple `KEY=value` form with shell-safe quoting when values contain
special characters.

## Install

Create the service user:

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin wordwarden
```

Install the binary and configuration directory:

```bash
sudo install -m 0755 wordwarden /usr/local/bin/wordwarden
sudo install -d -o root -g wordwarden -m 0750 /etc/authrim-wordwarden
sudo install -d -o root -g wordwarden -m 0750 /etc/authrim-wordwarden/ca
sudo install -m 0640 -o root -g wordwarden config.yaml /etc/authrim-wordwarden/config.yaml
sudo install -m 0640 -o root -g wordwarden wordwarden.env /etc/authrim-wordwarden/wordwarden.env
sudo install -m 0640 -o root -g wordwarden ldap-ca.pem /etc/authrim-wordwarden/ca/ldap-ca.pem
```

Install the unit:

```bash
sudo install -m 0644 deploy/systemd/authrim-wordwarden.service /etc/systemd/system/authrim-wordwarden.service
sudo systemctl daemon-reload
```

## Validate Before Start

Run config validation as the service user:

```bash
sudo -u wordwarden /usr/local/bin/wordwarden \
  --config /etc/authrim-wordwarden/config.yaml \
  config validate
```

Run LDAP diagnostics before starting the long-running service:

```bash
sudo -u wordwarden /bin/sh -c 'set -a; . /etc/authrim-wordwarden/wordwarden.env; set +a; exec /usr/local/bin/wordwarden \
    --config /etc/authrim-wordwarden/config.yaml \
    ldap test --tenant tenant-a'
```

For a user bind test:

```bash
printf '%s\n' "$USER_PASSWORD" | sudo -u wordwarden /bin/sh -c 'set -a; . /etc/authrim-wordwarden/wordwarden.env; set +a; exec /usr/local/bin/wordwarden \
    --config /etc/authrim-wordwarden/config.yaml \
    ldap test --tenant tenant-a --username alice --password-stdin'
```

## Start

```bash
sudo systemctl enable --now authrim-wordwarden
sudo systemctl status authrim-wordwarden
curl -fsS http://127.0.0.1:8080/healthz
```

Logs:

```bash
journalctl -u authrim-wordwarden -f
```

## Restart Boundary

Alpha does not reload configuration. Restart after changing any of:

- `config.yaml`
- HMAC secret refs or values
- LDAP bind password
- LDAP CA files
- tenant or connector ids
- timeout or protection settings

```bash
sudo systemctl restart authrim-wordwarden
```

`SIGHUP` is accepted only to report that reload is unsupported.

## Hardening Notes

The sample unit uses a restricted service account, no Linux capabilities,
`ProtectSystem=strict`, `NoNewPrivileges=true`, and namespace/device restrictions.

If your deployment needs to read CA or secret files from a path outside
`/etc/authrim-wordwarden`, update both the file permissions and the unit's
read-only path policy. Prefer keeping all Wordwarden runtime config under
`/etc/authrim-wordwarden`.
