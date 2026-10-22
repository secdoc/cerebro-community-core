# Capability boundary and source assessment

This standalone package contains no private deployment history or environment-specific source configuration. Its accepted scope is the bounded functionality below, not parity with any site-specific Cerebro deployment.

| Capability | Candidate status | Boundary |
|---|---|---|
| Portal core/API | Accepted, adapted from sanitized baseline | Read-only overview, integration listing, health/ready endpoints, self-hosted simplified UI. |
| Feed mapping | Accepted, narrowed | Adopter-supplied JSON object snapshots or unauthenticated, verified HTTPS GET-only JSON endpoints; exact origin allowlist, no redirects, bounded response, scalar summary field allowlist. Static planned entries supported. |
| State and provenance | Accepted | Healthy/degraded/stale/unavailable/unauthorized/planned, freshness, source metadata, no entity emission. |
| Native links | Accepted | Validated HTTPS only, user-provided, rel=noopener; links are navigation, not health evidence. |
| Single-host installer | Tested in isolated root only | Python 3.13/systemd Debian 13 target; dry-run/apply/one-step rollback, disabled unit by default, explicit gated activation. No live host install performed. |
| Private portal's 16+ technology views, branded artwork and original JS/CSS | Excluded | Private code, assets, assumptions and production-specific navigation not copied. Minimal public interface is a different scope, not visual parity. |
| Threat map, chart, GEOINT/WiGLE, network traffic | Excluded | No raw location/IP telemetry, third-party tiles or external map API; no matching public safe producers. |
| Vulnerability and CVE/asset investigation | Excluded | Requires separately reviewed producer snapshots, pseudonymization, entity association and API. |
| Threat-intelligence lookup, ATT&CK/ATLAS, threat model, risk register | Excluded | No source DB or governance files, no lookup APIs, no catalog mapping publication. |
| Agent Operations, God’s Eye View and OpenCTI | Excluded | No environment-bound producer scripts or live context copied. |
| Product-specific collectors (Wazuh, Graylog, Greenbone, Proxmox/PBS, Vault, Vaultwarden, Authentik, UniFi/Protect, Technitium, GitLab, Dependency-Track, Shuffle, Velociraptor, WAF) | Excluded | Generic summary mappings only; adopter supplies their own safe upstream data. No source auth, permissions, scheduling, or version-pinned integration asserted. |
| Auth proxy, TLS PKI, SSO/group policy | External prerequisite, not implemented | Installer checks unauthenticated HTTPS denial and requires operator attestation; adopter must implement and verify positive and negative identity/authorization tests. |
| Mutations, containment, workflow execution | Excluded | HTTP GET-only API; no response actions. |
| HA/cluster, backups of external source, secrets integration | Excluded | Single-instance candidate; external backups and identity gate remain adopter-owned. |

**No parity claim:** copying private integrations or their example topology without a complete security and portability review would create an unsafe release. This bounded portal is deployable as a read-only summary viewer when an adopter supplies trusted feeds and a separate authenticated proxy, not a turnkey security platform. Source-specific producer packaging and clean Debian/proxy acceptance remain release follow-ups.
