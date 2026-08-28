# Proton VPN for Omarchy Core

Shared runtime for [Proton VPN for Omarchy][plugin]. It provides the control
plane used by the native Omarchy plugin and is intended to be reusable by a
future standalone desktop client.

This repository is the browsable, buildable source corresponding to the
`proton-vpn-omarchy` 0.8.0-3 Arch package. The package is currently released
from the plugin repository so existing signed installer URLs remain stable.

This is an independent community project and is not affiliated with or
endorsed by Proton AG.

## Components

- `agent/`: per-user Rust agent and native Proton API/session control plane
- `protocol/`: versioned JSON Lines IPC types and examples
- `splitd/`: privileged Rust/eBPF split-tunneling enforcement service
- `packaging/`: Arch, systemd and D-Bus integration used by the release
- `vendor/local-agent-rs/`: pinned Proton Local Agent client with provenance
- `plugin/`: exact frontend snapshot bundled in the 0.8.0-3 package; current
  frontend development lives in the [plugin repository][plugin]

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

The exact 0.8.0 package recipe and metadata are tracked as
`packaging/arch/PKGBUILD` and `packaging/arch/.SRCINFO`. Release artifacts are
signed with the key in `RELEASE-SIGNING-KEY.asc`.

## Install

Use the guided, signature-verifying installer in the [Omarchy plugin][plugin].
It installs the matching package and configures systemd socket activation.
Manual package downloads remain available from the [0.8.0 release][release].

## Security and license

Report vulnerabilities privately through GitHub's security reporting flow.
Never attach Proton credentials, session tokens or personal VPN diagnostics to
a public issue.

Original project code is GPL-3.0-or-later. Vendored and upstream-derived files
retain their own notices and license files; see `NOTICE.md`.

[plugin]: https://github.com/48hoursnonstop/proton-vpn-omarchy
[release]: https://github.com/48hoursnonstop/proton-vpn-omarchy/releases/tag/v0.8.0
