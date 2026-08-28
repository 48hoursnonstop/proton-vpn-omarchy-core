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

The runtime integrates with the separately installed official Proton Linux API
core and ProTun NetworkManager service. Those Python packages and ProTun itself
are not redistributed in this repository.

All original project code is distributed under GPL-3.0-or-later. See LICENSE.
