# Proton VPN for Omarchy Quattro

This directory is a self-contained third-party Omarchy `bar-widget` plugin. It
runs inside the existing `omarchy-shell` process and delegates shared state to
`proton-omarchy-agent`; QML does not perform VPN, privileged networking, or
system-service mutations itself.

The bar entry follows Omarchy's rich popup-widget contract:

- `BarWidget.qml` is cheap at shell startup and creates `ProtonPanel.qml` only
  when the panel is first requested.
- The bar button uses `BarIconButton`'s 16 px optical canvas and
  `bar.barForeground`, including transparent-bar contrast and vertical bars.
- `KeyboardPanel` owns screen-aware positioning, outside-click dismissal,
  keyboard focus, multi-monitor dismissal, and one-popout-at-a-time handoff.
- Shell-level summon/hide routes select the focused monitor. The plugin IPC
  target remains available for Proton-specific connect/disconnect commands.
- Runtime presentation uses only Omarchy `Color`, `Style`, and `Ui` controls.

The signed-in panel follows the root-navigation layout of Proton VPN Android
at the inventory-pinned commit `cc1e29f8acd5f11f63701b48f97410e90fa6a71d`:

- a fixed Quattro viewport keeps the panel and bottom navigation stable while
  switching between Home, Countries, account-aware Gateways, Profiles and
  Settings;
- root destinations replace each other instead of building browser-like
  history;
- connection details, profile editing, location drill-down and settings
  subpages open above the root surface, hide the bottom navigation and return
  to their actual parent;
- Home contains the connection surface followed by Recents and favorites;
- left/right keyboard traversal switches root destinations, while Escape
  unwinds a nested page before it dismisses the panel.

The five root destinations use the exact outline/filled icon pairs selected by
the Android bottom bar: House, Earth, Servers, Window Terminal and Cog Wheel.
Their 24dp vector geometry comes from ProtonCore/Proton VPN Android; Quattro
owns their selected/dim color, logical size and display-scale response.
The icon and label are centered together as one optical group inside every
destination, so neither font metrics nor fractional display scale can shift one
away from the other.

The same official mobile icon language covers every plugin action surface:
settings, connection details, locations, profiles, recents, account, support,
diagnostics and split tunneling. ProtonCore vectors are theme-tinted by Quattro;
profile categories retain the exact colored Android WebP artwork. Country codes
remain text because they identify real data rather than standing in for icons.
Unicode abbreviations such as `NS`, `NAT`, `IP`, `PF` and `ST` are not used as
UI glyphs.

Enumerated settings use explicit one-choice lists. Protocol, Kill Switch,
NetShield, profile NetShield level and language never rotate to another value
just because their summary row was pressed; the user opens the choices and
selects the intended value directly. Binary preferences remain one-action
switches.

Only the information architecture is adapted from mobile. Every surface,
selection state, font, spacing value and scale response remains Quattro-owned.

The panel includes onboarding; SRP, TOTP, FIDO2, SSO and Human Verification;
Quick Connect; connection/protection controls; locations; recents; profiles;
connection details and NetShield statistics; split tunneling; settings;
account; support; diagnostics; and About. Spanish and English are backed by
the same shared Rust store as the standalone client.

The plugin is complete to its declared product scope. SSO, Human Verification,
connection feedback, P2P restriction notices, excluded locations and private
Connect and Go launches are native and active. IPv4/IPv6 Split Tunneling,
local-network access and local-name access are enforced by the authenticated
Rust policy service and inventoried in
`reference/plugin-capability-boundaries-2026-08-26.json`.

The compact Split Tunneling toggle enables Exclude mode using the saved app
list. It never silently disables Kill Switch or rewrites saved Include/Exclude
lists. The full page edits application paths and canonical IP/CIDR rules for
both modes; QML only submits the configuration and never enforces networking.

On the target system, the optimized idle Rust authority has no Python child.
The panel is lazy, traffic
sampling is visible-and-connected only, and startup opt-out lets an idle,
disconnected agent exit while systemd socket activation remains available.
