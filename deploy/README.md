# Deployment Samples

These samples are intentionally small Alpha deployment references.

Configuration changes require a process restart. `SIGHUP` is accepted only as an
operator signal that reports reload is not supported yet.

## systemd

Install the binary at `/usr/local/bin/wordwarden`, place configuration and secret
files under `/etc/authrim-wordwarden`, then install:

```bash
sudo install -m 0644 deploy/systemd/authrim-wordwarden.service /etc/systemd/system/authrim-wordwarden.service
sudo systemctl daemon-reload
sudo systemctl enable --now authrim-wordwarden
```

Restart after config, secret reference, LDAP CA, or tenant changes:

```bash
sudo systemctl restart authrim-wordwarden
```

## Docker Compose

Copy `deploy/docker-compose/compose.yaml` into an environment-specific directory,
mount a real `config.yaml`, and provide secrets through an env file or a secret
manager sidecar.

```bash
docker compose -f deploy/docker-compose/compose.yaml up -d
```
