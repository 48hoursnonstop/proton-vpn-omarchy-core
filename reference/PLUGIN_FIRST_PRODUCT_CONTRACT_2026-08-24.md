# Proton VPN for Omarchy — plugin-first product contract

Status: implemented and sealed to the declared plugin product scope,
2026-08-26. The exact completion matrix and upstream limits live in
`plugin-feature-completeness-2026-08-26.json` and
`plugin-capability-boundaries-2026-08-26.json`.

## Product decision

Proton VPN for Omarchy has two independent native frontends:

1. an Omarchy Quattro shell plugin; and
2. a standalone Qt Quick client derived from the frozen Windows behavior inventory.

They are not shells around one another. Neither frontend owns the other frontend's lifecycle or
visual system. They share exactly one local authority, `proton-omarchy-agent`, one authenticated
Proton session, one connection state and one canonical data store.

The plugin is the implementation priority. The standalone client remains a supported frontend,
but its visual port is deferred. Backend work required for the plugin must remain consumable by
both clients.

The plugin is a complete client surface, not a tray-only companion, mockup, prototype or temporary
handoff to the standalone app. Work may be delivered in vertical slices, but the product is not
complete until the complete scope and acceptance criteria below are satisfied.

## Authority hierarchy

- Omarchy Quattro 4.x is the plugin's visual, interaction, focus, panel and theme authority.
- Proton VPN Android at commit `cc1e29f8acd5f11f63701b48f97410e90fa6a71d` informs compact
  information architecture and supplies the official notification-status glyph family.
- Proton VPN Windows at commit `4d9ac60d1db5d3f2908498470a9d1646723afcfd` is the frozen
  completeness and product-behavior reference when the Linux implementation is missing a surface.
- Proton's official ProTun and NetworkManager OpenVPN services remain the tunnel-engine authority.
  The project-owned Rust control plane owns Linux orchestration and the Proton-compatible
  Split-Tunneling/LAN/local-name policy service.
- The sealed 1398-record A–L inventory is the discovery and traceability baseline. K covers compact
  shell/tray behavior; A–J and L remain the complete behavior and resource backlog.

Windows colors, window chrome, geometry and control tokens must not leak into the plugin. Android
screen layouts are not copied literally. Proton mark and status-glyph geometry may be reused, while
runtime colors, surfaces, type, spacing, focus and motion come from Quattro.

## Native plugin shape

- The plugin runs inside the existing long-lived `omarchy-shell` Quickshell process.
- It exposes one bar widget and one native Quattro panel. It does not create a second Quickshell
  process, independent tray item or notification daemon.
- The complete client remains panel-only. Mobile-style root navigation is adapted to the Quattro
  panel with a header/back stack, keyboard traversal and lazy pages.
- Primary destinations are Home, Countries, Gateways, Profiles and Settings. Gateways is shown
  only when the account/data makes it applicable.
- Search, server lists, connection details, profile editing and sub-settings use nested panel routes,
  not a separate large window.
- External system-browser handoff is allowed only for flows that inherently require a website,
  such as upgrade/account pages or an upstream-authenticated browser challenge. It is not a way to
  omit native client functionality.

The existing `plugin/` directory is archaeology and reusable source, not an accepted completeness
baseline. In particular, its current sign-in handoff and fire-and-forget request handling are
superseded by this contract.

## Complete functional scope

The plugin must eventually provide all Linux-supported product capabilities:

- onboarding, locale selection and shared-session discovery;
- standard Proton sign-in, sign-out and account state;
- SRP login, TOTP 2FA, FIDO2/WebAuthn security keys, Human Verification/CAPTCHA and SSO;
- Home status, Quick Connect, explicit connect/cancel/disconnect and connection details;
- Countries, cities, servers, search, Secure Core, P2P/Tor data and account-aware Gateways;
- Profiles create/read/update/delete, recents, favorites and Default Connection;
- connection protocol, NetShield, Kill Switch, DNS, VPN Accelerator, NAT/port forwarding and
  supported Split Tunneling controls with honest conflict/capability presentation;
- traffic information while the relevant page is visible and a connection exists;
- Settings, account/upgrade, support, report issue, diagnostics and applicable licensing/about data;
- localized inline feedback and system notifications;
- startup, logout, recovery, packaging and update/lifecycle integration appropriate to Arch/Omarchy.

Unsupported Windows-only behavior must not be fabricated. If an official Proton Linux capability is
absent, implementation first audits the official OSS references and extends the shared adapter when
that is safe and supported. Security-sensitive networking enforcement is never independently
reimplemented in contradiction with the official Linux core. A genuine upstream limitation is
shown truthfully and remains an open completion item where the product contract requires it.

## Shared IPC and operation model

The public boundary remains JSON Lines over
`$XDG_RUNTIME_DIR/proton-omarchy.sock`. QML never performs privileged networking. The socket and any
credential-bearing request path must remain private to the local user.

Every user-visible mutation is represented by a shared observable operation. An operation includes:

- stable operation ID and initiating client-instance ID;
- domain and kind;
- state: `queued`, `running`, `succeeded`, `failed` or `cancelled`;
- user-visible stage;
- start/update/finish timestamps and elapsed time;
- cancelability;
- typed error and retryability.

Credentials, 2FA values, challenge tokens and session secrets are never put in snapshots, operation
journals, logs or notifications.

The initiating frontend enters a local pending state immediately for first-round-trip feedback. The
agent's operation state then becomes canonical and is visible to both frontends. Reopening the panel,
reloading plugin code or reconnecting the socket restores the active operation instead of presenting
an idle or frozen UI.

### Scheduling and conflicts

The agent uses a central scheduler and explicit conflict matrix rather than one global FIFO or
unrestricted concurrent mutations:

- `auth/session`: login, TOTP, security key, Human Verification, SSO and logout are exclusive;
- `tunnel/configuration`: connection mutations and incompatible settings serialize;
- `support`: may run with tunnel work but not through auth/logout transitions;
- `store`: profile/history/preferences writes are atomic and independent;
- reads, cached snapshots and traffic observations do not wait behind long mutations.

A conflicting user action is rejected immediately with `operation_conflict` and information about
the active operation; clicks are not silently queued. Disconnect during Connecting cancels the
connection attempt. Logout is global, disconnects the VPN and invalidates the shared session only
after an explicit confirmation naming its effect on both clients.

## Authentication feedback and completeness

Authentication must never leave the panel apparently frozen. At minimum the shared backend exposes
stages such as submitting credentials, waiting for TOTP, waiting for a security key, waiting for a
browser/challenge, verifying, finalizing and loading the account.

TOTP submission shows immediate progress, remains cancelable where safe, returns typed invalid-code,
timeout and retry states, and keeps the correct challenge state after an error. The same recovery
discipline applies to every auth factor.

SSO is the first technical acceptance gate because the current Linux facade does not expose the
Windows SSO flow. The preferred complete solution is a real system-browser handoff without an
embedded WebView. The Windows OSS challenge-token flow and official Proton session APIs are evidence,
not permission to invent an incompatible authentication implementation. If the upstream protocol
cannot complete a secure browser handoff, that blocker must be documented with source evidence and
the no-WebView constraint revisited explicitly; SSO must not be claimed complete meanwhile.

## Canonical state and migration

Profiles, recents, favorites, Default Connection and shared preferences move from the Qt-only
`connection-store.json` into the agent-owned canonical store. Migration is one-time, non-destructive,
versioned and idempotent. Account data is namespaced by stable Proton account identity.

- Logout clears the session and transient operations.
- Profiles and preferences are retained per account by default.
- A later explicit delete-local-data control may remove retained account data.
- Agent autostart is device-global, not account-specific.
- Panel route and navigation depth live only in the shell process. The panel reopens where it was
  while `omarchy-shell` remains alive and returns to Home after shell/session restart.

Both frontends subscribe to canonical changes. A write from either client is reflected in the other;
neither client keeps a divergent authoritative profile/history database.

## Onboarding and startup

First run is one compact screen, not a carousel. It is shown even if a Proton session already exists
so the user can choose lifecycle behavior; existing auth then skips redundant sign-in.

- Language: Spanish (Mexico/Latin America) or English. `es-MX` is primary; English is fallback.
- `Start Proton VPN with Omarchy` is visible and ON by default, with explicit opt-out.
- `Connect automatically` is a separate option and OFF by default.
- When auto-connect is enabled, Default Connection supports Fastest, Random, Last, a recent target or
  a selected Profile, following mobile/Windows semantics.

Opt-out must be real. Merely loading the bar widget must not wake the agent and defeat disabled
autostart. Opening the panel or invoking an action may start the agent on demand. The agent may exit
when disconnected and idle; it stays available while a connection or required operation exists.

## Feedback and notifications

Foreground operations always have inline feedback. Omarchy system notifications are added when the
panel is closed, an operation is long-running, or an important state/error occurs. One central agent
emitter prevents duplicate notifications when both clients are open. Connection transitions replace
or update one notification rather than spamming a sequence.

Android notification semantics are preserved:

- `information`: informational/loading states;
- `disconnected`: disabled and terminal error/disconnected states;
- `connecting`: connecting, waiting for network, disconnecting, availability checks, port scans and
  reconnecting;
- `connected`: connected.

The official Android glyph geometry is used for these states. Quattro supplies runtime color and the
existing Freedesktop/Omarchy notification service supplies presentation and actions.

All UI strings and agent-generated notifications ship in `es-MX` and English. Errors cross IPC as
stable typed codes plus parameters; localization belongs at the presentation/emission boundary, not
as backend-only English prose.

## Lightweight contract

- No additional long-running plugin process; QML lives in `omarchy-shell`.
- The Rust agent is the sole local authority; no Python bridge or fallback is packaged.
- No Electron, embedded WebView, GTK frontend, Avalonia, X11 runtime or root UI.
- No periodic polling while the panel is closed.
- Traffic sampling runs only while connected and while a consumer is visible.
- Routes/components load lazily; country/server/app collections are virtualized.
- Search is debounced and cancellable.
- Snapshot caches and operation/event journals are bounded.
- State changes are pushed; the bar consumes a compact cached status.
- The bridge lifecycle must be demand-driven or idle-optimized without creating a second authority.

Implemented checkpoint: all plugin methods run in the native Rust backend. Bar presence, socket
hello and canonical store/onboarding/profile work remain Rust-only. The onboarding preference is
mirrored into a private watched lifecycle cache. With startup disabled,
the bar does not touch the agent socket; opening the panel uses the always-small systemd user socket
to activate the Rust agent on demand. QML never launches a process or calls systemd itself.

Target measurement of the optimized idle Rust agent is 4288 KiB RSS, zero CPU
scheduler ticks over four seconds and zero Python bridge children. The sealed
budgets are 32768 KiB, three ticks over four seconds and zero idle bridge
children. Correctness, truthful state and immediate feedback are not traded
away for these budgets.

## Packaging boundary

One Arch package owns the agent, split-policy service, assets, user service and third-party plugin
source. System-owned plugin source installs under `/usr/share/proton-vpn-omarchy/plugin`; only
`proton-omarchy-setup`, run unprivileged, integrates the user's plugin and shell configuration.
Packaging/install hooks never write `$HOME`. The package does not install or launch the Proton GTK
app and does not modify `/usr/share/omarchy`.

Opening and updating the standalone frontend remains independent from the plugin. Package updates
follow Arch/Omarchy conventions; Windows updater behavior is not copied as a fake in-app updater.

## Validation authorization

The earlier network restriction was explicitly lifted by the user. Build,
launch, authentication and connection validation are authorized. Connection
tests still preserve baseline topology, disconnect explicitly and report
cleanup evidence on failure.

## Implementation order

1. Extend the IPC contract with client instances, observable operations, typed conflicts/errors,
   capability data and localized notification parameters.
2. Replace global request serialization with the domain scheduler and recovery-safe shared operation
   model.
3. Close authentication backend gaps, treating SSO, FIDO2 and Human Verification as early technical
   acceptance gates.
4. Move profiles, recents, favorites, Default Connection and preferences into canonical agent
   storage with non-destructive migration.
5. Build the native Quattro panel shell, onboarding, auth routes and persistent operation feedback.
6. Add Home, connection details, Countries/servers/search, Gateways and traffic-on-demand.
7. Add Profiles CRUD, recents/favorites/defaults, complete settings/features and account surfaces.
8. Add support/report/diagnostics, Android-status notifications and lifecycle/recovery behavior.
9. Adapt the standalone client's backend integration without resuming its visual-port priority.
10. Validate lightweight budgets, dual-client consistency, packaging and complete acceptance gates.

## Definition of complete

"Complete" requires the full functional scope above, both locales, truthful capability handling,
recoverable operations across reload/reconnect, dual-client consistency, native Quattro behavior,
packaging/lifecycle closure and authorized validation evidence. A populated screen with fake data, a
disabled placeholder for a required supported capability, or a browser/full-app escape hatch for
native client work does not satisfy completion.
