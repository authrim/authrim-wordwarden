# Local Docker Compose Demo

This demo starts Authrim Wordwarden and a local OpenLDAP fixture. It is intended
for local verification of the beta password verification path, not for
production.

The demo user is:

- username: `alice`
- password: `password`
- email: `alice@example.com`

## Start

From the repository root:

```bash
./test/integration/openldap/generate-certs.sh
cp deploy/docker-compose/local-demo/.env.example deploy/docker-compose/local-demo/.env
docker compose -f deploy/docker-compose/local-demo/compose.yaml up -d --build
```

## Verify

OpenLDAP may take several seconds to finish its first TLS bootstrap. If the LDAP
diagnostic fails immediately after `up`, wait briefly and run it again.

Check the shallow process health endpoint:

```bash
curl http://127.0.0.1:8080/healthz
```

Expected response:

```json
{"ok":true,"connector":"authrim-wordwarden","version":"0.1.0-beta.1"}
```

Run an LDAP diagnostic through the Wordwarden container:

```bash
printf 'password\n' | docker compose -f deploy/docker-compose/local-demo/compose.yaml run --rm -T \
  wordwarden --config /etc/authrim-wordwarden/config.yaml ldap test \
    --tenant tenant-a \
    --username alice \
    --password-stdin
```

Expected output includes:

```text
tls_verified=true
service_bound=true
user_resolved=true
password_bind=true
```

Run the Authrim live integration test against the local Wordwarden endpoint:

```bash
AUTHRIM_WORDWARDEN_LIVE_INTEGRATION=1 \
  pnpm --dir ../authrim --filter @authrim/ar-auth test -- directory-password-live-wordwarden.test.ts
```

## Stop

```bash
docker compose -f deploy/docker-compose/local-demo/compose.yaml down -v
```

## Notes

- OpenLDAP is published on `127.0.0.1:1389` and `127.0.0.1:1636`.
- Wordwarden is published on `127.0.0.1:8080`.
- Wordwarden stores its demo `instance_id` under the local `./state` volume.
- The OpenLDAP fixture disables client certificate verification with
  `LDAP_TLS_VERIFY_CLIENT=never`; server certificate verification from
  Wordwarden to LDAP remains enabled.
- The Wordwarden HTTP listener uses plain HTTP for local demo only. Use HTTPS,
  a tunnel, or a private network path outside local development.
