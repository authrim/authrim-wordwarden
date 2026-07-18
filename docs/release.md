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
go run ./cmd/wordwarden --config config.example.yaml doctor
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

The release workflow is tag-driven. Pushing `v*` tags builds signed tarballs,
checksum manifests, a Go module SBOM, and the Docker image. The Docker image is
published to GitHub Container Registry when repository permissions allow package
publishing.

## Release Artifacts

The primary release artifacts are signed tarballs and a Docker image.

Expected tarball names:

```text
authrim-wordwarden_0.1.0-beta.1_linux_amd64.tar.gz
authrim-wordwarden_0.1.0-beta.1_linux_arm64.tar.gz
```

Each release must include:

- `SHA256SUMS`
- `SHA256SUMS.sig`
- `SHA256SUMS.bundle`
- `authrim-wordwarden_0.1.0-beta.1_sbom.json`
- Docker image digest in the release notes

Local release artifact build:

```sh
VERSION=v0.1.0-beta.1 ./scripts/build-release.sh
```

For controlled local testing only, unsigned artifact generation can be allowed:

```sh
WORDWARDEN_ALLOW_UNSIGNED_RELEASE=1 VERSION=v0.1.0-beta.1 ./scripts/build-release.sh
```

Do not publish unsigned artifacts.

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

## Installer Script

The Linux systemd installer is intentionally narrow. It installs the binary,
creates config/state directories, writes a systemd unit, and leaves LDAP,
relay, and secret configuration to the operator.

Dry run:

```sh
./deploy/install/install.sh --version v0.1.0-beta.1 --dry-run
```

Production install should verify both checksum and signature. `--skip-signature`
is for controlled testing only.

The installer constrains keyless Sigstore verification to the Wordwarden release
workflow identity and GitHub Actions OIDC issuer by default. Override
`--certificate-identity-regexp` and `--certificate-oidc-issuer` only for controlled
internal release channels.

## Update Check

Wordwarden does not auto-update in the initial managed offering. Operators check
the signed advisory feed and then manually install a verified release.

```sh
wordwarden update check \
  --feed-url https://example.com/wordwarden/stable.json \
  --trusted-feed-key <base64url-ed25519-public-key>
```

Unsigned feeds are accepted only for local file-based test fixtures when
`--allow-unsigned-feed` is set. Remote feeds must use `https://` and must carry
an Ed25519 signature. The signature covers the canonical JSON produced from the
advisory feed with the `signature` field omitted.

The advisory feed is JSON:

```json
{
  "channel": "stable",
  "latest_version": "0.1.0-beta.2",
  "release_url": "https://github.com/authrim/authrim-wordwarden/releases/tag/v0.1.0-beta.2",
  "advisories": [
    {
      "advisory_id": "WW-2026-0001",
      "affected_versions": ["0.1.0-beta.1"],
      "fixed_version": "0.1.0-beta.2",
      "severity": "high",
      "summary": "Short operator-facing summary",
      "published_at": "2026-06-27T00:00:00Z",
      "updated_at": "2026-06-27T00:00:00Z",
      "release_url": "https://github.com/authrim/authrim-wordwarden/releases/tag/v0.1.0-beta.2"
    }
  ],
  "signature": {
    "algorithm": "ed25519",
    "key_id": "wordwarden-release-2026-06",
    "signature": "base64url-signature"
  }
}
```

## Rollback

Rollback is manual in the initial scope:

1. Stop `authrim-wordwarden`.
2. Verify the checksum and signature for the previous release.
3. Replace the binary or Docker image digest with the previous release.
4. Start `authrim-wordwarden`.
5. Run `wordwarden version` and `wordwarden --config /etc/authrim-wordwarden/config.yaml doctor`.

Release notes must state whether local state is backward compatible.

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
- Release tarballs include checksum, signature, and SBOM artifacts.

Compatibility:
- Authrim 0.3.2 or later with Directory Authentication and Relay support.

Limitations:
- Public beta for controlled pilots.
- Configuration reload requires process restart.
- Complex group mapping and complete expired-password remediation are not yet
  included.
```
