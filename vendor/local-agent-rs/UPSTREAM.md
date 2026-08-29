# Upstream provenance

This directory vendors Proton VPN's pure-Rust Local Agent client so the native
backend does not depend on Python or on an absolute development checkout.

- Repository: https://github.com/ProtonVPN/local-agent-rs
- Package version: `0.10.1`
- Commit: `74ec6f4f093805d766f11f9ef522bf1120591058`
- Retrieved from the local frozen upstream inventory on 2026-08-26

Local hardening carried by this vendor snapshot:

- length-prefixed requests and responses are bounded before allocation;
- dependency metadata reuses this workspace's Tokio/Serde versions and the
  already-selected `x509-parser` release.

The GPLv3 license is copied from the same Proton VPN Linux source family
(`python-proton-vpn-api-core`).
