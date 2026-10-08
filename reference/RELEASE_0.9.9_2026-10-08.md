# 0.9.9 release validation — 2026-10-08

This release combines the reviewed LAN/startup corrections from PR #2 with
the three commits previously used by the local Windows 5.1.8 parity preview.
The historical parity checkpoint remains in
[WINDOWS_PARITY_IMPLEMENTATION_2026-09-22.md](WINDOWS_PARITY_IMPLEMENTATION_2026-09-22.md).

The first CI build under tag 0.9.8 exposed an auto-connect fixture whose
lifecycle path placed autostart links in a shared temporary directory.
The fixture now uses its own config/proton-vpn-omarchy directory. The parallel
workspace suite and all eight auto-connect tests pass with that isolation.
No 0.9.8 release was published; the failed tag is retained for traceability.

## Verification

- `cargo test --locked --offline --workspace --quiet`: 153 passed, zero failed,
  eight opt-in tests ignored. Only the three workspace package versions changed
  in Cargo.lock; dependency versions remain pinned.
- The production signed-catalog regression test verified all 18,879 active
  physical endpoints in the cached official v1 catalog. This resolves the
  checkpoint's missing production signature fixture without requesting a new
  VPN connection or exposing credentials.
- Isolated IPv4/IPv6 marked-route installation, cleanup and kill-switch
  fallback passed in a disposable user/network namespace. This is a routing
  test, not a claim of full eBPF packet-delivery validation.
- The disposable GNOME Keyring runner passed with passwordless and encrypted
  collections, delayed Secret Service startup, encrypted unlock in place and
  two daemon restarts per collection. Shared and unrelated synthetic entries
  survived. These tests do not use the desktop keyring.
- The matching plugin passed all 13 QML runtime fixtures, the installer fixture
  and the closed native Wayland host. Fixtures use synthetic state and floating
  offscreen windows. Two previously sandbox-limited fixtures passed in the
  full-access environment; an initial concurrent workspace run had a timing
  failure before the isolated and complete serial runs passed.

No live tunnel connection, reboot, host route change or keyring reset was
performed during release preparation. The user's current network is protected.

## Compatibility

The `Proton VPN for Omarchy` namespace and `pvom1:` / `pvom-index1:` envelopes
from 0.9.6-rc1 are unchanged. Session restoration and auto-connect remain
serialized; cancellation persists across delayed account restoration.

The package is backend-only. The plugin pins the exact signed CI package,
source tag/commit, byte sizes and SHA-256 digests. Local preview service
overrides must be removed when switching to the packaged backend; ordinary
installations have no such override.
