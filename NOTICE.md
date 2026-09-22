# Notices and provenance

Proton VPN for Omarchy Core is an independent community project. It is not an
official Proton product and is not affiliated with, sponsored by, or endorsed
by Proton AG. Proton, Proton VPN, and their product marks are trademarks of
their respective owners.

`vendor/local-agent-rs/` is a pinned copy of Proton VPN's GPL-licensed Rust
Local Agent client. Its upstream repository, version and commit are recorded
in `vendor/local-agent-rs/UPSTREAM.md`; its license is preserved alongside the
source.

The packaged plugin snapshot reuses or translates selected GPL-licensed icon
geometry and status assets from the Proton VPN Android and Proton Core Android
projects. Those assets retain their upstream copyright and license terms.

The one-time default connection-profile definitions mirror the GPL-licensed
Proton VPN Windows client at commit
`4d9ac60d1db5d3f2908498470a9d1646723afcfd`. They are normalized into this
project's canonical profile schema and remain editable user records.

Endpoint-signature validation, unambiguous city/state grouping, Smart Routing
metadata and connection-feedback timing follow the GPL-licensed Proton VPN
Windows client at commit `d2a4f8bc92a0fd296943a7cdd15f4f870c8a87f9` (v5.1.8).
The implementation and Linux verification boundaries are documented in
`reference/WINDOWS_PARITY_IMPLEMENTATION_2026-09-22.md`.

The runtime integrates with the separately installed official Proton Linux API
core and ProTun NetworkManager service. Those Python packages and ProTun itself
are not redistributed in this repository.

All original project code is distributed under GPL-3.0-or-later. See LICENSE.
