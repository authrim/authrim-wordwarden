# OpenLDAP Integration Fixture

This fixture starts a local OpenLDAP container with LDAPS enabled and a test user.

```bash
./test/integration/openldap/generate-certs.sh
docker compose -f test/integration/openldap/docker-compose.yml up -d
WORDWARDEN_LDAP_INTEGRATION=1 go test ./internal/adapters/ldap -run TestOpenLDAPIntegration
docker compose -f test/integration/openldap/docker-compose.yml down -v
```

Fixture credentials:

- bind DN: `cn=admin,dc=example,dc=com`
- bind password: `admin`
- user: `alice`
- user password: `password`
