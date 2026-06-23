# Release Process

This document describes the public beta release path for Authrim Wordwarden.

## Current Public Beta Target

- Version: `0.1.0-beta.1`
- Git tag: `v0.1.0-beta.1`
- License: Apache-2.0
- Compatible Authrim version: Authrim `0.3.2` or later with Directory
  Authentication and Authrim Relay support

## Pre-Release Checklist

Run these checks before tagging:

```sh
go test ./...
go run ./cmd/wordwarden --config config.example.yaml config validate
docker build -t authrim-wordwarden:ci .
git diff --check
```

Run a repository secret scan before public release:

```sh
git grep -n -I -E 'BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{20,}' -- . ':!docs/release.md'
git log --all --stat --oneline
```

Manual review must confirm that examples contain placeholders only and that no
real LDAP bind password, HMAC secret, tunnel token, tenant secret, or production
hostname is committed.

## Tagging

```sh
git tag -a v0.1.0-beta.1 -m "v0.1.0-beta.1"
git push origin main
git push origin v0.1.0-beta.1
```

The release workflow is tag-driven. Pushing `v*` tags builds and publishes the
Docker image to GitHub Container Registry when repository permissions allow
package publishing.

## Docker Image

Expected image name:

```text
ghcr.io/authrim/authrim-wordwarden:v0.1.0-beta.1
```

The image should be tested locally before publishing:

```sh
docker build -t authrim-wordwarden:v0.1.0-beta.1 .
docker run --rm authrim-wordwarden:v0.1.0-beta.1 version
```

## Release Notes Template

```text
Authrim Wordwarden v0.1.0-beta.1

Highlights:
- Directory password verification against LDAP/Active Directory.
- Direct HTTPS, Cloudflare Tunnel, and Authrim Relay deployment modes.
- HMAC connector authentication with active/previous key support.
- OpenLDAP local demo and deployment samples.

Security model:
- Wordwarden does not store plaintext passwords or password hashes.
- LDAP/AD remains the password source of truth.
- Relay mode avoids inbound connector exposure but still requires HMAC.

Compatibility:
- Authrim 0.3.2 or later with Directory Authentication and Relay support.

Limitations:
- Public beta for controlled pilots.
- Configuration reload requires process restart.
- Complex group mapping and complete expired-password remediation are not yet
  included.
```
