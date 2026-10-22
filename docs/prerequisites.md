# Prerequisites and acceptance checklist

## Host and security boundary

- Debian 13 amd64 or another Debian 13 architecture with `/usr/bin/python3` 3.13, systemd, `useradd`, enough disk for the package and snapshots, and root access for installation. The installation script refuses a non-Debian-13 live host.
- A network policy that makes port 8080 reachable **only on loopback**. Do not expose the Python server directly. Provide a separate TLS reverse proxy with a valid server certificate, user authentication, a documented authorization policy and audit logging. The installer does not install the proxy or configure an IdP.
- A named operator to verify unauthenticated denial, authenticated unauthorized denial, and authenticated authorized access on the exact public route. A 401/403 unauthenticated probe is necessary but not sufficient. Keep the systemd unit disabled until these checks pass.
- Source ownership, classification and allowed fields documented per feed. Grant the `cerebro` system user read access only to selected sanitized snapshot files. Do not expose raw events, credentials or arbitrary objects. The portal does not create producers or store their tokens.

## Feed association worksheet

For each feed, record: display name, stable ID, category, authoritative source and owner, JSON file path **or** exact trusted HTTPS GET endpoint and allowed origin, source timestamp field, boolean health or mapped state field, scalar summary fields, maximum age, expected cadence, and native console link. The wizard writes a config from this worksheet, but cannot establish producer identity, scheduling, schema validity or source-side permissions. An absent feed should not be entered as healthy. Start with zero feeds or a static planned entry and add one validated source at a time.

The current edition supports credential-free HTTPS GET using the host's standard CA store. Sources requiring a token, private CA override, POST authentication, or product-specific collection must publish a sanitized JSON snapshot through an independently secured producer. The producer and its schedule are outside this package. Review its ownership, rotation, last-known-good behavior, access path, and failure handling before enabling the corresponding portal entry.

## Before activation

1. Run repository tests, `scripts/scrub.py .`, wizard dry-run, installer dry-run and an isolated-root installation twice. The second run must report `changed=0`; exercise rollback.
2. Verify generated config has no secret values; confirm file ownership and mode on target. Test each selected feed's timestamp, summary allowlist, freshness and failure state, including malformed/stale/401/403/redirect where applicable.
3. Start the portal manually under `cerebro` on loopback, inspect `/api/v1/overview`, `/readyz` and method rejection. Check the dashboard in a normal authenticated browser, not only with curl.
4. Verify TLS chain and hostname, denied anonymous and unauthorized users, authorized user access, logout/session expiry and proxy logging. Check that direct TCP 8080 is not reachable from other hosts.
5. Activate with the installer gate and read back unit enabled/active state. Preserve the previous release and an off-host backup of adopter config, proxy policy and producers.

## Recovery limits

The installer receipt is a single-step local rollback, not a transactional deployment journal or backup. A failed mid-write install can leave a partial tree; use `--rollback --apply` and inspect files and service state before retrying. Rollback does not undo producer, IdP, proxy or network changes. A fresh-host restore must reestablish those dependencies and repeat the authorization and browser checks.
