# Authrim Wordwarden API

This document describes the Alpha HTTP contract between Authrim and Authrim
Wordwarden.

## Authentication

All password verification requests are authenticated with
`AUTHRIM-HMAC-SHA256`.

Required headers:

- `X-Authrim-Connector-Id`: connector id resolved from the Authrim tenant
- `X-Authrim-Key-Id`: active or previous key id
- `X-Authrim-Request-Id`: request id, also present in the JSON body
- `X-Authrim-Timestamp`: RFC3339 timestamp, accepted within a two minute clock skew
- `X-Authrim-Nonce`: nonce for replay protection
- `X-Authrim-Signed-Headers`: semicolon-separated signed header names
- `X-Authrim-Signature`: lowercase hex HMAC-SHA256 signature

`X-Authrim-Signed-Headers` must include `content-type`,
`x-authrim-connector-id`, `x-authrim-key-id`, `x-authrim-request-id`,
`x-authrim-timestamp`, and `x-authrim-nonce`. Wordwarden lowercases,
deduplicates, and sorts the signed header names before verifying the signature.
Each signed header must appear exactly once on the request.

Canonical request:

```text
AUTHRIM-HMAC-SHA256
<timestamp>
<nonce>
<method>
<escaped-path>
<canonical-query>
<canonical-headers>
<signed-headers>
<sha256-body-hex>
```

`<canonical-headers>` is one line per signed header, sorted by lowercase header
name, in the form `<name>:<value>`. Header values are trimmed and internal
whitespace is collapsed to a single space. This binds the connector id, key id,
request id, timestamp, nonce, and content type to the signature, not just the
JSON body.

The HMAC secret is tenant/connector scoped. Wordwarden accepts the configured
active key and, if present, one previous key for rotation.

## POST /v1/auth/verify-password

Request body:

```json
{
  "request_id": "req_123",
  "tenant_id": "tenant-a",
  "connector_id": "ww_tenant_a",
  "username": "alice",
  "password": "correct horse battery staple",
  "attribute_names": ["uid", "mail", "displayName"]
}
```

`tenant_id`, `connector_id`, and `request_id` must match the authenticated
headers and configured connector runtime. Requested attributes are intersected
with the connector-local allowlist before LDAP lookup.

Success response:

```json
{
  "request_id": "req_123",
  "tenant_id": "tenant-a",
  "connector_id": "ww_tenant_a",
  "result": "success",
  "subject": {
    "directory_id": "uid=alice,ou=People,dc=example,dc=com",
    "username": "alice"
  },
  "attributes": {
    "uid": ["alice"],
    "mail": ["alice@example.com"]
  },
  "directory_status": "ok"
}
```

Invalid credentials response:

```json
{
  "request_id": "req_123",
  "tenant_id": "tenant-a",
  "connector_id": "ww_tenant_a",
  "result": "failure",
  "reason": "invalid_credentials",
  "directory_status": "ok"
}
```

Credential verdicts use HTTP `200`. Transport, authentication, malformed
request, replay, storm-limit, and directory availability failures use HTTP
errors.

## Error Codes

| HTTP | Code | Retryable |
| --- | --- | --- |
| 400 | `malformed_request` | false |
| 401 | `unsigned_required_hmac_header` | false |
| 401 | `malformed_signed_header` | false |
| 401 | `missing_hmac_header` | false |
| 401 | `invalid_hmac_timestamp` | false |
| 401 | `stale_hmac_timestamp` | false |
| 401 | `unknown_hmac_key` | false |
| 401 | `invalid_hmac_signature` | false |
| 413 | `payload_too_large` | false |
| 403 | `unknown_connector` | false |
| 403 | `tenant_connector_mismatch` | false |
| 409 | `replay_detected` | false |
| 429 | `connector_rate_limited` | true |
| 429 | `hmac_failure_storm_limited` | true |
| 429 | `malformed_request_storm_limited` | true |
| 429 | `replay_storm_limited` | true |
| 503 | `directory_unavailable` | true |
| 503 | `directory_tls_error` | true |
| 503 | `directory_error` | true |
| 503 | `directory_error_storm_limited` | true |

## Health

`GET /healthz` is intentionally shallow in Alpha. It returns process status and
version only; it does not test LDAP reachability.
