# Samba AD Integration Fixture

This fixture starts a local Samba Active Directory Domain Controller for guarded
Wordwarden LDAP integration tests. It is intended for local compatibility checks,
not for production or CI-by-default use.

The container exposes LDAP on `localhost:1390`. The fixture disables Samba's
"strong auth" LDAP requirement so the local test can use plain LDAP on the
loopback interface. Production deployments should use LDAPS or StartTLS with
certificate verification.

## Start the fixture

```sh
docker compose -f test/integration/samba-ad/docker-compose.yml up -d --build
```

Wait for the container to become healthy:

```sh
docker ps --filter name=wordwarden-samba-ad
```

## Run the guarded test

```sh
WORDWARDEN_SAMBA_AD_INTEGRATION=1 go test ./internal/adapters/ldap -run TestSambaADIntegration
```

Defaults used by the test:

| Setting | Value |
| --- | --- |
| LDAP URL | `ldap://localhost:1390` |
| Realm | `EXAMPLE.TEST` |
| Base DN | `CN=Users,DC=example,DC=test` |
| Bind DN | `Administrator@EXAMPLE.TEST` |
| Bind password | `Passw0rd!` |
| Test username | `alice` |
| Test password | `Password123!` |

## Stop the fixture

```sh
docker compose -f test/integration/samba-ad/docker-compose.yml down -v
```

## Real AD smoke test

The same Go test file also contains a real AD smoke test guarded by
`WORDWARDEN_REAL_AD_INTEGRATION=1`. Set the documented environment variables in
that test when checking a customer or lab domain controller.
