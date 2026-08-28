# proton-omarchy protocol

Public frontend/agent protocol: **v1 JSON Lines**.

The plugin-first extension remains additive protocol v1 and adds concurrent request correlation,
per-client instance identity, typed error details and shared observable operations. Active operation
state is pushed with every canonical snapshot; the initiating socket can receive progress while its
request is still pending. Incompatible mutations fail immediately with `operation_conflict`.

The same additive contract exposes official-core FIDO2 authentication with observable key-touch,
selection, PIN and cancellation stages. Security-key PIN controls attach to the active auth
operation and never enter the canonical journal.

The plugin-first contract also adds Rust-owned canonical store methods for onboarding,
preferences, profiles, recents and Default Connection. Collection reads are paginated and store
writes are observable `store` operations. `connection.resolve` expands Fastest, Random, Last,
Recent or Profile into one canonical connection request without crossing the Python bridge.

M11 is an additive v1 extension. It adds:

- `apps.get`
- `split_tunneling.set`
- full split-tunneling app-list state and backend capability flags

The public socket remains `$XDG_RUNTIME_DIR/proton-omarchy.sock`, mode `0600`, with 64 KiB
frames and push snapshots. No frontend polling is introduced.

0.50 adds the source-ported web-account hand-off request without changing protocol version:

- `account.upgrade_url` — authenticated `web-account-lite` session fork for Upgrade; exact AccountUrl fallback; never initializes `VPNConnector`.

0.69 adds GUI lifecycle observation without changing protocol version:

- `connection.observe` — signed-in GUI lifecycle request mirroring frozen GTK connector initialization; creates/registers `VPNConnector` and publishes its current state without Connect/Disconnect/settings mutation. Agent-only startup remains passive.

0.70 does not add a protocol method. It corrects the Qt client-side pre-snapshot state contract: connection status is `unknown` until an authoritative observation arrives, matching `connection.observation_known=false`.

0.71 does not add a protocol enum value. The frozen Windows client deliberately maps transport `Disconnecting` to client `Disconnected`; the bridge now maps Linux `states.Disconnecting` into the existing protocol `disconnected` value rather than misreporting it as `connecting`.
