# Passwordless Migration Without Password Storage

Authrim Wordwarden is designed for migrations where Authrim does not become a
password store. Authrim must not import, hash, rehash, or persist user password
credentials. That includes hashed passwords from a legacy system.

The supported authentication choices are:

- Passkey
- Email Code
- Directory Connector through Wordwarden
- External IdP, such as social login, OIDC, or SAML

Wordwarden only verifies a submitted directory password against LDAP/AD and
returns a short credential verdict to Authrim. The password remains transient in
the verification request and is never stored by Wordwarden or Authrim.

## Migration Patterns

### Directory-Backed Bridge

Use this when LDAP/AD remains the password authority during the transition.

```text
Existing LDAP/AD account
  -> Wordwarden directory verification
  -> Authrim session
  -> Passkey enrollment or application login
```

Recommended use:

- keep LDAP/AD as the password authority
- enable Directory Connector for the tenant
- return only the minimal attributes needed for Authrim user matching
- progressively enroll Passkeys
- keep Email Code available as a recovery or bootstrap method

Do not export LDAP/AD password hashes into Authrim.

### Email-Code Bootstrap

Use this when live LDAP/AD password verification is not available or should not
be used for a population.

```text
SCIM/CSV profile import
  -> Email Code or invitation verification
  -> Passkey enrollment
```

Recommended use:

- import user profile data only
- use email ownership as the bootstrap factor
- require Passkey enrollment after bootstrap where policy allows
- keep Directory Connector disabled for this cohort if LDAP/AD should not be used

SCIM or CSV inputs must not include plaintext passwords, password hashes, hash
algorithms, salts, or legacy password envelopes.

### External IdP Bootstrap

Use this when an upstream IdP already owns authentication.

```text
External IdP login
  -> Authrim account/session
  -> optional Passkey enrollment
```

Recommended use:

- use OIDC, SAML, or social login as the external authority
- map stable external subject identifiers to Authrim users
- use SCIM/CSV only for profile provisioning when needed
- avoid duplicating the upstream IdP's password credential in Authrim

## SCIM and CSV Rules

SCIM and CSV are profile provisioning channels for this migration path. They may
carry identifiers, names, email addresses, lifecycle status, and mapped profile
attributes.

They must not carry:

- plaintext passwords
- password hashes
- password hash algorithms
- salts
- password reset secrets
- legacy hash envelopes

If a SCIM client sends the standard SCIM `password` attribute, Authrim rejects
the request instead of hashing or storing it.

## Operational Boundary

Operators should be able to explain the boundary this way:

- LDAP/AD, External IdP, Passkey, or Email Code proves the user.
- Authrim creates sessions and federation output.
- Wordwarden verifies LDAP/AD passwords without becoming a directory or IdP.
- No Authrim component stores user password credentials.

If password-hash import ever becomes necessary, it must be designed as a future
milestone with a separate threat model, explicit retention rules, and a clear
exit path back to passwordless authentication.
