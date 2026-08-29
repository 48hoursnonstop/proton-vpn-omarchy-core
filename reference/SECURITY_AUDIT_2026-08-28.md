# Security audit — 2026-08-28

Scope: the Rust agent, privileged split-tunneling service, local IPC, browser
authentication, NetworkManager profiles, vendored Local Agent client, package
installer, release workflow, and the independently distributed QML frontend.

## Threat boundaries

- The QML frontend and agent run as the desktop user. The agent socket is
  `0600`; another process running as that same Unix user can request normal UI
  operations, but the protocol never returns Proton access or refresh tokens.
- Split tunneling crosses into a root D-Bus service. Mutating calls authorize
  the D-Bus caller UID against the target UID, and persisted state is bounded
  and stored `0600`.
- Network services are authenticated with HTTPS. Proton API responses are
  additionally SPKI-pinned and response bodies are bounded.

## Findings remediated

- Replaced the loopback DevTools WebSocket used for SSO/CAPTCHA with Chromium's
  inherited `--remote-debugging-pipe`. No unauthenticated debugging endpoint or
  bearer-bearing browser session is now exposed on a TCP port.
- Restricted SSO callbacks to the exact HTTPS Proton API origin.
- Bounded Chromium control frames, DNS-over-HTTPS replies, cached JSON,
  desktop-entry files, and Proton Local Agent frames before allocation.
- Kept the production server catalog bounded at 64 MiB while retaining the
  tighter 4 MiB API limit for authentication and support responses. Cache
  failures are isolated so replaceable catalog data cannot discard a valid
  keyring session or reset privacy/network settings.
- Prevented desktop-entry scans from following directory symlink cycles and
  capped scan depth/count/query size.
- Corrected split-tunneling executable matching so `/usr/bin/fire` does not
  match `/usr/bin/firefox`.
- Disabled HTTP redirects in pinned API and fixed-provider DoH clients.
- Made diagnostics/statistics files consistently replace with mode `0600`.
- Changed usage statistics to explicit opt-in and added a one-time migration
  from the older implicit-true default. The crash-report switch is read-only
  until a real crash upload implementation exists.
- Removed credential strings from request JSON before authentication work and
  zeroized password, 2FA code, and security-key PIN buffers.
- Made corrupt individual keyring sessions non-fatal and bounded the account
  index maintained by this client.
- Added bounded Tokio runtime shutdown so a stuck blocking FIDO/keyring worker
  cannot force systemd to escalate every normal stop to `SIGKILL`.
- Hardened the per-user systemd service without blocking Chromium sandboxing,
  FIDO devices, NetworkManager, or the desktop Secret Service.

## Dependency review

`cargo-audit` was run against the RustSec database current on 2026-08-27.
`RUSTSEC-2023-0071` is present through `rsa -> pgp -> proton-srp`. This client
uses that chain only to verify Proton's signed SRP modulus (a public-key
operation), not for an RSA private-key operation exposed to attacker-selected
ciphertexts, so the advisory's timing attack is not reachable in this use.
There is no fixed `rsa` release available in the dependency line today.

The vendored Proton Local Agent snapshot also pulls packages marked
unmaintained (`bincode 1.x`, `rustls-pemfile 2.x`), and Mozilla's FIDO
implementation pulls `serde_cbor 0.11`; none has a known vulnerability in this
graph. The Local Agent provenance and local hardening delta are recorded in
`vendor/local-agent-rs/UPSTREAM.md`.

## Residual limitations

- Linux does not provide a strong security boundary between arbitrary desktop
  processes sharing one Unix UID. A sandbox/portal architecture would be
  required to prevent same-user denial-of-service requests to the agent.
- Crash reporting is intentionally not implemented or writable yet; the UI
  must not claim reports are being transmitted.
- Security-key behavior depends on the Mozilla `authenticator` crate and local
  USB/HID access. Cancellation and shutdown are bounded, but a kernel/device
  stall cannot be made memory-safe by application logic alone.
- The Local Agent protocol is authenticated with Proton-issued client
  certificates. Frame limits protect availability but cannot make a malicious
  Proton endpoint trustworthy beyond that certificate boundary.

No credentials, session data, local configuration, or machine-specific values
were included in this audit record.
