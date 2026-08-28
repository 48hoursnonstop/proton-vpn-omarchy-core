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
Manual package downloads remain available from the [0.8.4 release][release].

## Security and license

Report vulnerabilities privately through GitHub's security reporting flow.
Never attach Proton credentials, session tokens or personal VPN diagnostics to
a public issue.

Original project code is GPL-3.0-or-later. Vendored and upstream-derived files
retain their own notices and license files; see `NOTICE.md`.

[plugin]: https://github.com/48hoursnonstop/proton-vpn-omarchy
[release]: https://github.com/48hoursnonstop/proton-vpn-omarchy-core/releases/tag/v0.8.4
