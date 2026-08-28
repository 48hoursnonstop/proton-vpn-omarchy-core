# proton-omarchy-agent — plugin-first 0.8.2

Per-user Rust service on `$XDG_RUNTIME_DIR/proton-omarchy.sock`.

Protocol v1 includes two typed public operations:

- `apps.get` — paginated installed-app catalog returned by the Rust backend.
- `split_tunneling.set` — atomic enabled/mode/app-list update.

The Rust agent remains responsible for framing, request correlation, canonical state and
same-user socket access. Split-tunneling enforcement remains in Proton's privileged Linux daemon.

When startup is opted out, the agent exits after 30 idle seconds if no client,
operation or live tunnel needs it. Socket activation starts it again on demand.

## Plugin-first operation scheduler

The agent now keeps the canonical bounded operation journal shared by every frontend. Socket
sessions do not await backend work inside their read/push loop, so 2FA, connection and support work
cannot suppress progress events to the initiating client. Authentication, tunnel/configuration,
support and future store writes use explicit conflict rules; there is no invisible global click
queue. The in-process Rust backend is the only control-plane authority.

FIDO2 PIN and cancellation calls are explicit controls attached to the active security-key
operation. This keeps a single observable auth lifecycle while allowing the initiating socket to
respond to a hardware prompt without deadlocking behind its own request.

## Canonical store

The Rust process owns the shared frontend store under
`$XDG_DATA_HOME/proton-vpn-omarchy/state-v1.json` (or the XDG default). It persists with a private
directory, `0600` file and atomic replacement. Profiles and recent connections are account-scoped;
onboarding and lifecycle choices are device-global. A legacy Qt store is read once and left intact.
Store requests are handled in Rust and do not initialize tunnel networking.

The agent contains one in-process Rust backend. Merely loading the bar, connecting a frontend
socket, completing onboarding or reading the canonical store does not create a VPN connection.

`proton-omarchy-agent.socket` provides systemd user-socket activation. The plugin watches the
private lifecycle cache written by the canonical store: auto-start opt-out prevents bar-time socket
access, while opening the panel may still activate the Rust agent on demand. The startup preference
adds/removes only the known `proton-omarchy-agent.service` user-unit symlink and refuses to replace
unrelated files.
