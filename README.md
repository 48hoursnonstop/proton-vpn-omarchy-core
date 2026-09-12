# Proton VPN for Omarchy Core

Shared runtime for [Proton VPN for Omarchy][plugin]. It provides the control
plane used by the native Omarchy plugin and is intended to be reusable by a
future standalone desktop client.

This repository is the browsable, buildable source for the
`proton-vpn-omarchy` backend package. Starting with 0.8.1, the package contains
only the shared core: the independently updated frontend lives in the plugin
repository.

This is an independent community project and is not affiliated with or
endorsed by Proton AG.

## Components

- `agent/`: per-user Rust agent and native Proton API/session control plane
- `protocol/`: versioned JSON Lines IPC types and examples
- `splitd/`: privileged Rust/eBPF split-tunneling enforcement service
- `packaging/`: Arch, systemd and D-Bus integration used by the release
- `vendor/local-agent-rs/`: pinned Proton Local Agent client with provenance

The signed `v0.8.0` tag preserves the historical frontend snapshot bundled in
the 0.8.0-3 package. It is intentionally absent from current releases so a
backend package can never downgrade a Git-managed plugin.

Proton's official ProTun NetworkManager service is an external runtime
dependency. Its implementation is not copied into this repository or claimed
as project code.

## Build and test

On Arch Linux with Rust 1.75 or newer:

```bash
cargo build --locked --release --package proton-omarchy-agent
cargo build --locked --release --package proton-omarchy-splitd
cargo test --locked --workspace
```

The exact package recipe and metadata are tracked as
`packaging/arch/PKGBUILD` and `packaging/arch/.SRCINFO`. Release artifacts are
produced from a signed exact tag by the pinned GitHub Actions workflow in
`.github/workflows/release.yml`. Cargo dependencies are locked, the Arch build
container and repository snapshot are pinned, and GitHub publishes a Sigstore
build-provenance bundle for the package. The unchanged CI artifact is then
signed with the publisher key in `RELEASE-SIGNING-KEY.asc` before the draft
release is made public.

To reproduce a release source archive and Arch package from a checked-out tag,
run `packaging/release/build-release VERSION OUTPUT_DIRECTORY`. The command
rejects a source digest or version that differs from the tracked release
recipe and uses the tracked `packaging/release/SOURCE_DATE_EPOCH`.

## Install

Use the guided, signature-verifying installer in the [Omarchy plugin][plugin].
It installs the matching package and configures systemd socket activation.
Manual package downloads are available from the [0.9.6 release][release].
The stable Arch package is `0.9.6-2`, which upgrades the `0.9.6-1` candidate
without changing the RC1 keyring format or requiring another sign-in.

## GNOME Keyring compatibility

Omarchy's passwordless default GNOME Keyring stores secrets in a textual
GKeyFile. Escaped control characters in raw JSON sessions—most visibly
newlines in PEM material—can be reinterpreted when the GNOME Keyring daemon
restarts.

Starting with 0.9.6, Proton VPN for Omarchy stores writable session state in
its own Secret Service namespace, `Proton VPN for Omarchy`. Session payloads
and the account index use versioned ASCII-only Base64URL envelopes (`pvom1:`
and `pvom-index1:`), so raw JSON, PEM data and control characters are never
written directly to the passwordless GKeyFile.

Existing shared Proton SSO entries under the `Proton` service are treated only
as a one-time migration source. The core can read and repair a legacy session,
validate it, import it into the private namespace, and then leave the shared
Proton entries untouched. Signing out removes only Proton VPN for Omarchy's
private session and does not delete shared Proton credentials.

Session refreshes retain the 0.9.6-rc1 storage format and update only the
session item when the account order and import marker are unchanged. Session
and index payloads are validated before writing. Sign-out records the
no-reimport marker before deleting the private session, so interrupted index
cleanup cannot silently restore a shared legacy login on restart. Duplicate
account names are normalized without changing their order of preference.

Base64URL provides representation safety, not encryption. On Omarchy's
passwordless keyring, confidentiality at rest still depends on the host's
storage encryption and access controls. The core does not delete or recreate
the user's keyring.

If credentials from unrelated applications disappear, preserve
`~/.local/share/keyrings` before troubleshooting; that indicates a broader
keyring problem rather than cleanup performed by this package.

### Keyring regression checks

The 0.9.7-rc1 candidate also recovers sessions when Secret Service starts late
or the desktop keyring is initially locked. The account remains `restoring`
until storage can be read; it is not treated as a fresh sign-out. Retries back
off from one second to a maximum interval of 30 seconds. The plugin can request
an immediate retry with `account.retry_restore`.

Passwordless collections can unlock silently. Password-protected collections
wait for desktop authentication without repeated unlock dialogs. Saved VPN
settings remain loaded throughout, and auto-connect runs once the account is
available. The 0.9.6-rc1 credential envelopes and private namespace are unchanged.

The normal Rust test suite uses an in-memory Secret Service for migration,
token refresh, sign-out, locked storage and interrupted writes. It checks
that shared Proton and unrelated credentials are untouched, and that all
private payloads remain ASCII-safe, including sessions containing multiline
PEM data, control characters and Unicode.

To test empty, locked, delayed-start and restarted GNOME Keyring storage, with
synthetic credentials and temporary XDG directories on a private D-Bus session:

```bash
python3 tests/keyring-roundtrip.py
```

This requires Python 3, `dbus-run-session`, `gnome-keyring-daemon`, `gdbus`
and cached Cargo dependencies. The runner checks both passwordless GKeyFile
and password-protected collections across two daemon restarts each. Host
D-Bus service activation is disabled, and temporary data is removed afterward.

An additional ignored test can validate an existing private desktop session
with the account owner's consent. It reads and round-trips credentials in
memory without writing, importing legacy data, contacting Proton or printing
account identifiers and secrets:

```bash
PROTON_KEYRING_READ_ONLY_TEST=1 cargo test --locked --offline \
  --package proton-omarchy-agent \
  native_backend::secret_store::tests::desktop_private_session_is_rc1_compatible_read_only \
  -- --ignored --exact
```

## Security and license

Report vulnerabilities privately through GitHub's security reporting flow.
Never attach Proton credentials, session tokens or personal VPN diagnostics to
a public issue.

Original project code is GPL-3.0-or-later. Vendored and upstream-derived files
retain their own notices and license files; see `NOTICE.md`.

[plugin]: https://github.com/48hoursnonstop/proton-vpn-omarchy
[release]: https://github.com/48hoursnonstop/proton-vpn-omarchy-core/releases/tag/v0.9.6
