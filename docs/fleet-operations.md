# Connector Fleet Operations Runbook

This runbook covers Authrim Wordwarden Connector Fleet operations for direct,
Cloudflare Tunnel, and outbound Relay deployments.

Connector Fleet is an operational control surface, but instance registration and
instance deactivation affect authentication availability. Treat Fleet actions as
security-sensitive operations.

## Trust Boundaries

- `connector_id` identifies the Authrim connector. It is immutable and is not a
  human label.
- `instance_id` identifies one Wordwarden runtime instance. It is generated on
  first startup and stored under `server.state_dir`.
- `display_name` is only an operator-facing label. It must not be used as an
  identity boundary.
- Heartbeat keys are separate from password verification keys.
- Heartbeat payloads must not contain LDAP passwords, LDAP bind secrets, user
  passwords, user attributes, bind DN values, base DN values, or raw filters.

## Normal Operating State

A healthy connector instance should show:

- status: `connected`
- recent `last_seen_at`
- expected Wordwarden version
- health status: `healthy`
- drift severity: `none`
- expected config categories

For direct or tunnel deployments, Wordwarden sends heartbeat requests to Authrim.
For relay deployments, Wordwarden reports fleet metadata during the existing
WebSocket authentication path.

## Triage Order

When a tenant reports directory password login failures:

1. Open Authrim Admin UI -> Directory Authentication -> Connector Fleet.
2. Check whether all instances or only one instance are affected.
3. Check the current episode start time to identify when the failure started.
4. Check `last_seen_at`:
   - stale or missing heartbeat usually indicates network, tunnel, or process failure.
   - connected but unhealthy usually indicates local LDAP/AD reachability or config issues.
5. Check drift severity:
   - `critical` drift means security-sensitive or endpoint/profile categories changed.
   - `warning` drift means non-secret operational settings differ.
6. Check Wordwarden host logs and `GET /healthz/details` when operations endpoints
   are enabled on loopback.
7. Use `wordwarden ldap test --tenant <tenant_id>` from the connector host.
8. Confirm Authrim directory connector settings still point to the intended immutable
   `connector_id`.

Do not expose low-level HMAC, connector mismatch, or deactivation reasons to end
users. End-user messages should stay generic and actionable.

## Acknowledge

Use `acknowledge` after an operator has seen the current episode and opened or
completed the incident work.

Acknowledgement is not a fix. A new episode or status transition should become
unacknowledged again.

## Deactivate

Deactivate a single instance when:

- the host may be compromised;
- the instance is running an unexpected binary or version;
- the instance has critical drift that cannot be explained;
- duplicate state directories caused an unexpected `instance_id` collision;
- an instance should be removed from active service before maintenance.

Deactivation rejects future heartbeat and relay registration for that
`instance_id`. It does not affect other instances under the same connector.

After security-related deactivation:

1. Rotate the heartbeat key.
2. If relay or password verification secrets may also be exposed, rotate those
   keys separately.
3. Rebuild or re-provision the host.
4. Start Wordwarden with a persistent `server.state_dir`.
5. Reactivate only when the instance identity and host state are expected.

## Reactivate

Reactivate only after verifying:

- the host is expected and under operator control;
- the `instance_id` belongs to the intended Wordwarden installation;
- heartbeat key rotation has been completed when the deactivation was security-related;
- local LDAP/AD tests pass;
- Authrim connector settings still reference the intended immutable `connector_id`.

Reactivate changes the instance back to a recoverable disconnected state. The
next valid heartbeat or relay registration should move it to connected or
unhealthy.

## Rolling Upgrade

Use at least two Wordwarden instances when the connector is business-critical.
For a rolling upgrade:

1. Confirm the current fleet has at least two healthy instances.
2. Upgrade one instance at a time.
3. Keep `server.state_dir` persistent across the upgrade so `instance_id` remains stable.
4. Wait for the upgraded instance to report `connected` and expected version.
5. Check drift categories. Expected version changes should not introduce critical
   config drift.
6. Repeat for the next instance.
7. After all instances are upgraded, acknowledge any maintenance episodes.

If only one instance exists, schedule a maintenance window or temporarily provide
another login method such as Passkey, Email Code, or External IdP.

## State Directory Handling

`server.state_dir` must be persistent. If it is deleted, Wordwarden generates a
new `instance_id` and Authrim will show a new fleet instance. This is acceptable
for rebuilds, but it loses continuity for status episodes tied to the old
instance.

Recommended permissions:

- directory: `0700`
- `instance_id` file: `0600`
- owner: the Wordwarden service user

## Heartbeat Key Rotation

Heartbeat keys use active and previous slots.

1. Add the new key as active in Authrim and Wordwarden.
2. Move the old key to previous while all instances restart or reload through the
   deployment process.
3. Confirm all instances report with the new key ID.
4. Remove the previous key after the operational grace period.

Do not reuse password verification keys as heartbeat keys.

## Incident Evidence

For incident notes, record:

- tenant ID;
- connector ID;
- affected instance IDs;
- current episode `started_at` and `last_seen_at`;
- Fleet action taken: acknowledge, deactivate, reactivate;
- whether heartbeat, relay, or password verification keys were rotated;
- Wordwarden version before and after remediation.

Do not record raw LDAP passwords, HMAC secrets, bearer tokens, or full LDAP
filters in incident notes.
