# 0.9.11 — Correct packet marks and recover blocked API access

This release fixes two split-tunneling marking errors, continuously observes
owned tunnels, refreshes remote account/configuration data and adds bounded
foreground Stealth Guest Hole recovery.

- IPv6 destination keys no longer overwrite the UID used for policy lookup.
  Reused UDP sockets recompute their mark for every destination using the
  current application policy. A previous IP/LAN/DNS bypass no longer carries
  into the next send, and unrelated marks are preserved.
- Owned-tunnel state is observed with the panel closed. Unexpected disconnects
  use bounded recovery; manual actions and external VPNs do not trigger it.
- Sign-out deletes the private local session before best-effort remote revoke,
  bounded to five seconds. Shared Proton credentials remain untouched.
- Account plan and client configuration refresh periodically. `account.refresh`
  supports manual refresh; missing/stale configuration is recovered before
  connection. Physical location is invalidated when the network changes and
  fetched only without VPNs.
- Guest Hole may recover foreground login, manual account refresh or connection
  preparation through a temporary Stealth tunnel when Alternative Routing is
  enabled. Cancellation and exact-UUID cleanup precede ordinary VPN activation.
- The Arch ProTun metadata hook recognizes `/usr/lib` and `/usr/libexec` without
  accepting arbitrary executable paths. Guest profiles keep the DNS entry that
  NetworkManager normalization and the installed ProTun service require.

The companion plugin 0.9.11 fixes Qt 6.12 color resolution and exposes account
refresh and Guest Hole cancellation. Its installer pins this exact signed and
attested package.

## Validation and remaining coverage

172 Rust tests pass; nine opt-in tests are skipped in the normal run. Four
corrected destination programs pass the kernel verifier without attachment.
Disposable IPv4/IPv6 route/kill-switch tests, ProTun metadata rollback and
libnm normalization regressions pass. The companion frontend passes 14 QML
fixtures, the closed native host and installer checks.

Authenticated Stealth tunnels and HTTPS traffic succeeded on three test servers
in Mexico, the Netherlands and Switzerland. A repeated Mexico test verified
changed egress using two independent HTTPS services and IPv4 routing through
the VPN interface. No test-account identifiers, addresses or credentials are
included in published evidence.

Guest Hole applies temporary full-tunnel routing and tunnel DNS. It preserves
existing VPNs and blocking kill switches. The installed Linux ProTun v1 contract
supports direct endpoints; relay-only bootstrap entries are skipped. Complete
Guest Hole API recovery, reconnection after a real drop and the complete
IPv6/UDP/split/kill-switch traffic matrix remain unverified.

Automatic crash uploads remain excluded by community-project scope. English
and Spanish remain supported. Keyring namespaces and `pvom1:`/`pvom-index1:`
envelopes remain compatible with 0.9.6-rc1; JSON Lines v1 and profile formats
remain compatible.

## Package and provenance

Install the matching plugin and backend **0.9.11-1**. The Arch package is built
from the signed exact tag in the pinned GitHub Actions environment. Its CI
artifact receives GitHub/Sigstore build provenance and a detached signature
from the existing published release key. The guided installer verifies the
source tag/commit, provenance, signature, exact sizes and SHA-256 values.
