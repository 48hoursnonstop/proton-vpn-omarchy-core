# Windows 5.1.8 parity — implementation checkpoint

This historical checkpoint is superseded for release validation by
[the 0.9.8 report](RELEASE_0.9.8_2026-10-08.md), which includes the production
signed-catalog fixture and subsequent connection fixes.

Branch: `feat/windows-5.1.8-parity`, based on core 0.9.7. This is an
implementation checkpoint, **not a released or installed build**. The initial
[0.9.7 audit](WINDOWS_UPSTREAM_REVIEW_2026-09-22.md) and its reproducer remain
historical evidence.

Reference: Proton Windows
[`d2a4f8bc92a0fd296943a7cdd15f4f870c8a87f9`](https://github.com/ProtonVPN/win-app/tree/d2a4f8bc92a0fd296943a7cdd15f4f870c8a87f9),
version 5.1.8. The frontend implementation is on the same named branch in
`proton-vpn-omarchy`.

## Implemented

- **Endpoint validation:** requests `SignServer=Server.EntryIP,Server.Label`
  on catalog and server-name lookup. Preserves null versus empty `Label`;
  verifies the compact signed JSON with the upstream pinned Ed25519 key;
  validates IP and X25519 key format. The signature covers EntryIP and Label,
  **not** the X25519 key or the rest of the catalog. Invalid physical endpoints
  are skipped within the requested target; both OpenVPN and ProTun constructors
  independently reject invalid signatures before profile/credential creation.
  A replacement target is validated before disconnecting an existing tunnel.
- **Cache upgrade:** unsigned catalogs refresh before connecting. One signed
  lookup cannot incorrectly mark an otherwise unsigned cache as migrated.
  Expired signed catalogs refresh opportunistically; if refresh fails, cached
  endpoints still undergo signature verification at selection and construction.
  Unsigned endpoints never receive this fallback. An expired access token during
  mandatory migration uses the existing session-persistence path after refresh.
- **Cities:** infer a missing state only when that country/city has exactly one
  known state. Apply the same mapping to Standard/P2P subdivisions, server lists,
  profile/target selection and exclusion matching. Ambiguous homonyms remain
  separate.
- **Smart Routing:** expose physical host code/name in server and connection IPC,
  aggregate distinct host countries in country groups, and clear connection
  metadata on disconnect. Frontend lists/search, Home and Details present this
  information separately from exit country and Secure Core entry.
- **Feedback:** read `variant.payload.value` of `IsConnectionFeedbackEnabled`,
  accepting 1–300 seconds and defaulting to 10. The frontend counts only while
  Details exposes the question, pauses during feedback requests/navigation,
  keeps the same budget across reopening, and resets on a new connection.
  Dismissal records `ignore`, not a positive/negative vote, and preserves the
  statistics opt-in. Fade uses existing Omarchy motion settings. Old backends
  without the timeout field do not receive the new dismissal action.
- **Linux name resolution:** set NetworkManager `connection.llmnr = 0` only on
  this client's VPN profiles, consistent with the documented
  [per-interface setting](https://www.networkmanager.dev/docs/api/latest/settings-connection.html).
  No global desktop, physical-interface, mDNS, NetBIOS or disk-unlock settings
  are changed.

The Linux catalog endpoint remains `/vpn/v1/logicals`; the requested signature
fields and verification bytes follow Windows. Windows's current full-catalog
request uses v2, while its legacy integration client also requests signatures
on `/vpn/logicals`. **Actual signed v1 response compatibility must be verified
before release.** No claim is made that the Windows ProTun binary fixes were
ported into the separately distributed Linux engine.

## Verification performed

```sh
cargo fmt --all -- --check
cargo test --locked --offline --workspace
cargo test --locked --offline --package proton-omarchy-splitd \
  isolated_dual_stack_marked_routes_and_kill_switch -- --ignored --nocapture
```

- Workspace: **142 passed**, 7 opt-in tests ignored (including the signed
  production-catalog fixture and the namespace test run separately).
- Isolated Linux route test: **passed**. Creates its own user/network namespace,
  invokes the actual splitd route installation/cleanup functions, and checks
  IPv4/IPv6 marked bypass, cleared marks selecting the tunnel, routes to VPN DNS
  addresses, and blackhole fallback after tunnel-route removal. It never changes
  the host's network namespace. This verifies routing after marking, **not**
  actual eBPF attachment, packet delivery, DNS resolution or NM activation.
- Frontend: **11 offscreen runtime fixtures passed**, plus the closed native
  Wayland host. New fixture verifies physical-host labels in EN/ES and timer
  visibility, pause/resume, one-shot dismissal, reconnect reset and duration
  fallback. The existing workspace fixture had one timing failure during a
  concurrent build; its isolated retry and the final complete run passed.
- Signature tests cover synthetic valid signatures, tampering, wrong keys,
  missing/malformed signatures, null/empty/escaped labels, cache round-trip,
  unsigned migration detection, candidate fallback and both tunnel constructors.
  The test signing key is never trusted by production validation.
- IPC tests round-trip host metadata and timeout values, retain the distinction
  between physical host, exit and Secure Core entry, and clear on disconnect.

## Release validation still required

A direct signed-catalog request timed out from this environment. A pinned
alternative-routing probe failed with `tls_pin_mismatch`; the pinned sets
still match the Windows reference. Other official API probes returned HTTP
401/403. TLS/pinning was not disabled. **No signed production response or live
VPN connection was verified**, and no credentials were read or written in
these checks.

Before packaging a release:

1. Obtain the signed catalog with an authenticated Proton session over the
   normal trusted API transport. Verify its active physical endpoints with:

   ```sh
   PROTON_SIGNED_CATALOG_PATH=/path/to/signed-catalog.json \
     cargo test --locked --offline --package proton-omarchy-agent \
       official_catalog_fixture_verifies_with_the_production_key -- --ignored --nocapture
   ```

   The file contains public catalog metadata only, not session tokens. This
   check has **not** been run successfully here. Confirm the v1 query contract
   or deliberately migrate catalog parsing/exit-IP handling to v2 if required.
2. Exercise a legacy unsigned cache upgrading into a real ProTun connection;
   check a second connection from the signed cache, and OpenVPN if available.
3. Run the privileged eBPF/packet and NetworkManager integration checks in an
   isolated lab, including IPv6-capable/incapable servers and DNS behavior.
   The namespace route test does not replace those checks.

The deployed 0.9.7 version and installer pins are unchanged. No release, push,
installation, tunnel change or desktop configuration change was performed.
