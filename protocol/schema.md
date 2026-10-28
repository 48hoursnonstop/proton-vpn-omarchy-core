# JSONL protocol v1 — passive bootstrap contract

Each frame is one UTF-8 JSON object terminated by `\n`, maximum 64 KiB.

## Saved-session recovery (0.9.7)

`account.status=restoring` means that the initial credential read has not
completed successfully. Clients should show a waiting state and hide the login
form. A locked or unavailable keyring does not mean the user signed out.
Background recovery retries with exponential backoff capped at 30 seconds;
`account.retry_restore` with empty parameters requests an immediate retry and
returns `{ "logged_in": true|false }` on a successful read. Storage failures
remain retryable errors and leave the account in `restoring`.

`account.get` remains a cached read. Login/logout and authenticated controls
return `keyring_unavailable` while restoration is pending. Once storage is
read successfully, the account becomes `signed_in` or (for an empty keyring)
`signed_out`. Auto-connect observes the signed-in transition independently of
whether the plugin is open. No credential format or namespace changes are
part of this protocol addition.

## Concurrent requests and observable operations

`hello.params.client_instance_id` identifies one frontend instance. It is bounded to 128 ASCII
letters, digits, `.`, `_`, `:` or `-`. Older clients may omit it; the agent then assigns a
socket-session identifier and returns the effective value in the hello response.

After hello, one client may have up to 32 requests in flight. Responses may arrive out of order and
must be correlated by request ID. A long request never blocks `state.changed` delivery on the same
socket.

Every user-visible mutation is published in `StateSnapshot.operations`:

```json
{
  "operations": {
    "active": [
      {
        "id": "op-0000000000000001",
        "initiator_client_instance_id": "plugin-shell-7f3a",
        "domain": "auth_session",
        "kind": "account.submit_2fa",
        "state": "running",
        "stage": "auth.verifying_two_factor",
        "started_at_unix_ms": 1787533200000,
        "updated_at_unix_ms": 1787533200200,
        "finished_at_unix_ms": null,
        "cancelable": false,
        "error": null
      }
    ],
    "recent": []
  }
}
```

Domains are `auth_session`, `tunnel_configuration`, `support` and `store`. States are `queued`,
`running`, `succeeded`, `failed` and `cancelled`. Stage values are stable localization keys, not
English UI copy. The recent journal is newest-first and bounded to 16 records.

The scheduler rejects incompatible work immediately rather than silently queuing a click:

```json
{
  "type": "response",
  "v": 1,
  "id": "18",
  "ok": false,
  "error": {
    "code": "operation_conflict",
    "message": "Another incompatible Proton VPN operation is already running",
    "details": {"active_operation": {"id": "op-0000000000000001"}},
    "retryable": true
  }
}
```

`message` is a compatibility/diagnostic fallback. Frontends localize from `code`, `details` and
operation `stage`. Credentials, 2FA codes and auth tokens never appear in operation records, errors,
snapshots or journals.

Authentication conflicts with authentication, tunnel/configuration and support mutations. Tunnel
and configuration mutations serialize with each other. Support may run alongside tunnel work, while
duplicate support submissions conflict. Store writes are atomic and independent of network work.
Cached/read requests do not wait behind long mutations; authenticated reads receive an immediate
conflict while the shared session itself is changing.

`servers.get` accepts the bounded pagination fields `offset` and `limit`, plus `query`,
`country_code`, `gateway_name`, `feature`, and `scope`. Search queries match server names rather
than expanding a country or city into every server at that location. `scope` is `consumer`,
`gateways`, or `all`, so a gateway search cannot leak into the consumer catalog.
`servers.lookup` accepts a complete server-name query and is intended for a delayed exact lookup
after local results are empty; successful remote results are retained in the in-memory catalog so
the selected server can be connected without a second fetch.

## Authentication and security keys

Credentialless guest login is not advertised on Linux. Proton's production API currently limits
that flow to Android and iOS device challenges; exposing an unusable method would make capability
negotiation dishonest. `account.credentialless` remains in snapshots for forward compatibility
and for reading any already-persisted session that may carry the flag. Account web hand-off opens
the Proton signup page instead of attempting a session fork.

Credential login and authenticator-code 2FA use the official `ProtonVPNAPI.login()` and
`submit_2fa_code()` paths. `account.two_factor_code_supported` and
`account.two_factor_security_key_supported` describe the methods available while
`account.status=two_factor_required`.

The official Linux core also owns the complete FIDO2 assertion and validation path:

```json
{"v":1,"id":"20","type":"request","method":"account.authenticate_fido2","params":{}}
```

Progress is published through the active operation (`auth.scanning_security_keys`,
`auth.select_security_key`, `auth.touch_security_key`, `auth.security_key_pin_required`,
`auth.verifying_security_key`). If the key requests a PIN, the same frontend submits it without
interrupting the active assertion:

```json
{"v":1,"id":"21","type":"request","method":"account.submit_fido2_pin","params":{"pin":"<redacted>"}}
```

Cancellation uses `account.cancel_fido2`. PIN and cancellation requests attach to the active FIDO2
operation rather than conflicting with it. The PIN is passed only through the private socket and a
bounded in-memory handoff; it is never stored in snapshots, operation records or journals.

Organization SSO and human verification are implemented by the native Rust
backend through a bounded external Chromium debugging pipe. There is no embedded
WebView or Python runtime bridge. Authentication errors retain typed codes.

`account.refresh` updates plan information and replaceable client configuration;
it reports `account_updated`, `client_config_updated` and `location_updated`.
Physical location is refreshed only without an active VPN and is invalidated on
physical network changes. Token renewal alone is not an account refresh.

`account.logout` records the no-reimport marker and deletes the private local session before
best-effort remote revocation. It returns `logged_out:true` independently of
network availability, plus `remote_revoked` for the bounded remote attempt.

Guest Hole is negotiated as `api.guest_hole.stealth`. When Alternative Routing
is enabled, foreground login/account refresh/connection preparation may recover
transport failures through a temporary Stealth tunnel. Background reads and
physical-location lookups cannot start it. An existing VPN or active blocking
kill switch is preserved. `guest_hole.cancel` cancels recovery; connection Cancel
also interrupts its operation. Stages are `guest_hole.connecting`,
`guest_hole.requesting`, and `guest_hole.cleaning_up`. Temporary profiles never
appear as an authenticated/Protected connection and are removed before the real
VPN is activated. The official Linux engine applies temporary full-tunnel routes;
this is not a per-app routing promise. See the current implementation report.

## Canonical frontend store

Onboarding, locale, startup choices, profiles, recents and Default Connection are owned by the Rust
agent. Store requests stay inside Rust and never initialize Proton networking. The
small bounded summary is pushed in every state snapshot:

```json
{
  "store": {
    "revision": 4,
    "ready": true,
    "onboarding_complete": true,
    "locale": "en",
    "start_with_omarchy": true,
    "auto_connect": false,
    "account_scope_known": true,
    "profile_count": 2,
    "recent_count": 4,
    "default_connection": {"type":"profile","profileId":"profile-..."},
    "migration_available": true
  }
}
```

Collections use bounded requests instead of enlarging every pushed snapshot:

```json
{"v":1,"id":"30","type":"request","method":"profiles.list","params":{"offset":0,"limit":50}}
{"v":1,"id":"31","type":"request","method":"recents.list","params":{"offset":0,"limit":50}}
{"v":1,"id":"32","type":"request","method":"connection.resolve","params":{}}
```

`connection.resolve` is a Rust-only read. With no selection it resolves Default Connection; an
explicit `{"selection":{"type":"recent","recentId":"..."}}` or profile selection uses the same
authority. It returns validated `connect_params` and an optional canonical recent to record after
the frontend has submitted `connection.connect`.

Mutations are `onboarding.complete`, `preferences.set`, `profiles.save`, `profiles.duplicate`, `profiles.delete`,
`recents.record`, `recents.pin`, `recents.delete` and `default_connection.set`. They use the
observable `store` operation domain, atomic same-directory replacement, a 1 MiB total store cap,
128-profile cap and six-unpinned-recent policy. The file and its dedicated directory are private to
the user. Existing Qt `connection-store.json` data is imported once without modifying or deleting
the source, then copied into the first known account scope.

## Passive bootstrap invariants

Startup loads the private session and saved policy, reconciles owned protection
and split rules, removes orphaned recovery profiles, and observes NetworkManager.
It does not start Guest Hole. Auto-connect and resume recovery follow the saved
preference and manual-cancellation rules. `connection.observe` is a cached-control
read of NetworkManager and includes `owned`; the agent also polls it independently
of frontend visibility so terminal states cannot remain stale.

The backend state therefore separates these facts instead of exposing a single `ready` bit:

```json
{
  "backend": {
    "kind": "proton_rust",
    "core_available": true,
    "connection_available": true,
    "connection_availability_known": true,
    "settings_known": true,
    "connector_initialized": false,
    "core_version": null,
    "error": null
  },
  "connection": {
    "observation_known": false,
    "status": "unknown",
    "profile_id": null
  }
}
```

When a stored profile created the observed tunnel, `connection.profile_id` is its exact store
identifier. It is persisted as private metadata on the unsaved NetworkManager connection, so the
association survives GUI or agent restarts without inferring identity from server settings.

`connector_initialized=false` is the expected **agent-only** idle-startup state. `status=unknown`
is not an alias for `disconnected`. After a signed-in GUI requests `connection.observe`, the
expected state is `connector_initialized=true`, `connection.observation_known=true`, with the
actual NetworkManager `Connected` / `Disconnected` / `Error` / transitional state. This lifecycle
observation is required to represent a VPN connection that survived a GUI process restart.

Split Tunneling has an independent `availability_known` field; once GUI lifecycle observation
initializes the connector, its exact capability can also become known.

Request:

```json
{"v":1,"id":"9","type":"request","method":"connection.observe","params":{}}
```

The method requires a signed-in account and performs no connection or settings mutation.

## Device location observation

The Windows `DeviceLocationObserver` is mirrored as a read-only state surface. The native backend
queries Proton's unauthenticated `vpn/location` endpoint only when NetworkManager has no active
VPN/WireGuard tunnel, and republishes changes as part of `StateSnapshot`:

```json
{
  "device_location": {
    "known": true,
    "ip_address": "203.0.113.20",
    "country_code": "MX",
    "isp": "Example ISP",
    "latitude": 19.4326,
    "longitude": -99.1332
  }
}
```

The native maintenance loop checks the physical network identity every 30 seconds
while no foreground operation is active. It uses active Ethernet/Wi-Fi addresses
and gateways, invalidates a location on physical-network changes, and fetches a
replacement only without active VPNs. Failed requests retry after 60 seconds;
account refresh also requests a location refresh when safe. Both network identity
and VPN state are checked again before accepting the response. Cached fields may
remain in the snapshot with `known:false`; clients must honor that flag. The
observer never activates a tunnel or Guest Hole.


## Account web hand-off

`My account` is intentionally not an IPC request: the frozen Windows client opens
`https://account.protonvpn.com/account` directly. Upgrade uses the authenticated Proton session:

```json
{"v":1,"id":"45","type":"request","method":"account.upgrade_url","params":{"modal_source":"Countries"}}
```

Successful authenticated result shape:

```json
{"url":"https://account.proton.me/lite?...#selector=<redacted>","authenticated":true}
```

If the official Proton session fork fails or produces no selector, the exact Windows fallback is:

```json
{"url":"https://account.protonvpn.com/account","authenticated":false}
```

The method may call Proton's authenticated `/auth/v4/sessions/forks` web-session endpoint, but it
never initializes `VPNConnector` and never changes NetworkManager, routes, DNS, Kill Switch, or a
VPN connection. Selectors are short-lived authentication material and must not be logged.


## Report an issue submission

The frozen Windows UI serializes the selected category and dynamic field values. The Rust core
sends this optional report directly to Proton's official bug-report endpoint and supplies Linux OS
metadata. This is separate from community GitHub issues. The UI request is:

```json
{"v":1,"id":"46","type":"request","method":"report_issue.submit","params":{"category":"Something else","email":"user@example.com","fields":{"What went wrong?":"Description"},"include_logs":true}}
```

Logs are opt-in: omitting `include_logs` is equivalent to `false`. When explicitly set to `true`,
the core collects three bounded Linux sources: the `proton-omarchy-agent.service` user journal,
the last day of NetworkManager journal, and the `proton.VPN.service` split-tunneling journal.
Sources are best-effort; one unavailable source does not discard the user's report.

The report identifies itself as the unofficial Proton VPN for Omarchy community client. It sends
the signed-in account name, entered email, current country/ISP when available, selected description,
and the opted-in attachments directly to Proton AG. Frontends must disclose that destination and
obtain explicit confirmation. The community issue flow never calls this method.

`diagnostics.get` returns a shareable `summary` that excludes account names, IP addresses,
connection IDs, raw API errors, and journal contents. It is intended for the community GitHub issue
template; raw journals remain local unless the user separately opts into the official Proton report.

The Rust transport uses Proton's official multipart report contract with truthful metadata
(`Title=Report from Proton VPN for Omarchy (unofficial community client)`, `Client=Linux GUI`).
The `Client` value is retained for Proton's Linux routing contract; the title, description and
repository URL identify the actual community product. Submission never initializes or mutates a
VPN connection, DNS, routes, Kill Switch, or NetworkManager state.

The target validation gate sets `PROTON_OMARCHY_REPORT_ISSUE_DRY_RUN=1`. That exercises form
validation, description serialization and diagnostic collection but intentionally skips the HTTP
request, so automated validation can never create a customer-support ticket.

## Installed applications

Request:

```json
{"v":1,"id":"40","type":"request","method":"apps.get","params":{"offset":0,"limit":50,"query":"fire"}}
```

Response result:

```json
{
  "offset": 0,
  "limit": 50,
  "total": 1,
  "apps": [
    {"name":"Firefox","executable":"/usr/lib/firefox/firefox"}
  ]
}
```

The catalog is advisory UI data. Split-tunneling persistence stores executable strings, matching
Proton Linux's settings model. Frontends may also add a manual executable/Flatpak command.

## Split Tunneling state

```json
{
  "split_tunneling": {
    "mode": "off|standard|inverse",
    "availability_known": true,
    "available": true,
    "app_paths_supported": true,
    "ip_ranges_supported": true,
    "standard": {
      "app_paths": ["/usr/bin/example"],
      "ip_ranges": ["192.0.2.0/24"]
    },
    "inverse": {
      "app_paths": ["/usr/bin/another-app"],
      "ip_ranges": ["2001:db8::/32"]
    }
  }
}
```

Public mode mapping:

- `standard` = Proton `SplitTunnelingMode.EXCLUDE`
- `inverse` = Proton `SplitTunnelingMode.INCLUDE`
- `off` = split tunneling disabled; the saved per-mode lists are retained

## Atomic update

```json
{
  "v":1,
  "id":"41",
  "type":"request",
  "method":"split_tunneling.set",
  "params":{
    "enabled":true,
    "mode":"standard",
    "standard":{"app_paths":["/usr/bin/firefox"],"ip_ranges":["192.0.2.0/24"]},
    "inverse":{"app_paths":["/usr/bin/steam"],"ip_ranges":["2001:db8::/32"]}
  }
}
```

The request carries both application and IP/CIDR lists so switching mode never destroys the
inactive configuration. IPv4/IPv6 hosts are converted to `/32` or `/128`; CIDRs are truncated to
their canonical network address before persistence and enforcement.

## Validation

- at most 128 app entries per mode;
- each entry is bounded to 4096 UTF-8 bytes;
- embedded NUL/newline characters are rejected;
- at most 256 IPv4/IPv6 host or CIDR entries per mode;
- the active mode requires at least one selected application or IP range when enabled;
- Kill Switch and Split Tunneling may be enabled together. Excluded sockets receive the
  Proton-compatible mark and a UID-scoped policy route to the active physical gateway; unmarked
  traffic continues to follow Kill Switch and therefore remains fail-closed;
- unavailable Proton split service returns `split_tunneling_unavailable`;
- malformed IP/CIDR entries return `invalid_split_ip_ranges`.

The agent does not execute an app entry as a command. The privileged Rust service authenticates
the caller UID, persists the complete configuration atomically, and enforces destination rules in
UID-scoped IPv4/IPv6 LPM maps. TCP/connected UDP are handled at connect hooks; unconnected UDP is
handled at sendmsg hooks. Only the established Proton bypass mark is written.

## Search location connection targets

The frozen Windows global Search returns Country, State, City and Server location items. State
and City actions use the existing `connection.connect` method with an explicit location target:

```json
{
  "v":1,
  "id":"59",
  "type":"request",
  "method":"connection.connect",
  "params":{
    "target":{
      "country_code":"US",
      "state":"New York",
      "city":"New York"
    }
  }
}
```

`country_code` is required whenever `state` or `city` is present. Standard location targets
exclude Secure Core, Tor and B2B gateway logicals before choosing the fastest available server.
P2P may be combined with State/City and keeps the same location filters. Tor, Secure Core and
gateway modes cannot be combined with State/City because the frozen Windows Search does not
create those location-item combinations. `state` is read from the immutable `State` field in
the Proton logical-server payload and is carried read-only through the agent snapshot.

Profiles keep their location hierarchy separate from their selection strategy. A target with
`random=true` chooses an eligible country uniformly and then that country's best logical server,
matching Windows' Random country behavior. `random_server=true` instead chooses a logical server
after explicit country/state/city/gateway filters have been applied. `exclude_my_country=true`
removes the country reported by Proton for the current physical connection from automatic
selection; the request fails retryably if that device location is unavailable. Country-random
and server-random cannot be combined in one request.

## Profile connection settings

A profile connection may attach a client-persisted `profile_settings` object to the existing
`connection.connect` request:

```json
{
  "v":1,
  "id":"60",
  "type":"request",
  "method":"connection.connect",
  "params":{
    "target":{"country_code":"CH"},
    "profile_settings":{
      "protocol":"wireguard-udp",
      "netshield_enabled":true,
      "netshield_level":2,
      "moderate_nat":false,
      "port_forwarding":false,
      "custom_dns":{"mode":"custom","servers":["1.1.1.1","2606:4700:4700::1111"]},
      "allow_lan_connections":true,
      "allow_local_dns":false
    }
  }
}
```

These values are **per-connection overrides**. The Rust agent clones global settings, validates
the profile and builds an ephemeral NetworkManager profile; it never persists the overrides as
global settings. Older profiles resolve `custom_dns.mode`, LAN and local-DNS policy to `inherit`.
Custom DNS modes are `inherit`, `off` and `custom`; a custom list contains at most 16 canonical
IPv4/IPv6 addresses. Explicit custom DNS and NetShield are rejected together. When DNS is
inherited, an explicit profile NetShield choice keeps its existing precedence over global custom
DNS.

`allow_lan_connections` and `allow_local_dns` are booleans or `null` (`null` means inherit). Their
destination routing is installed before tunnel activation and the global policy is restored while
the tunnel is still up during disconnect. A failed restoration leaves the tunnel up rather than
carrying profile-only bypass routes into a disconnected state.

Windows `VpnProtocol` mapping used by this port:

- `Smart` → `protun-smart`
- `WireGuardUdp` → `wireguard`
- `ProTunUdp` → `protun-udp`
- `ProTunTcp` → `protun-tcp`
- `ProTunTls` → `protun-tls`
- `OpenVpnUdp` → `openvpn-udp`
- `OpenVpnTcp` → `openvpn-tcp`

The frozen Linux API-core has no separate WireGuard TCP/TLS protocol classes, so those two
Windows choices are capability-disabled rather than mapped to a different backend.
`moderate_nat=true` and `port_forwarding=true` together are rejected. Paid connection features
are rejected for Free-tier accounts instead of being silently ignored by the local agent.

- `report_issue.categories.get` — read-only dynamic Report-an-issue category provider with frozen Windows fallback validation.
- `report_issue.submit` — user-triggered multipart report submission through the native API transport; verification does not send real reports.

### VPN Accelerator


### Protocol settings

`features.protocol.selected` is the normalized persisted native protocol identifier.
`features.protocol.available` is derived from installed official NetworkManager
services. ProTun supplies UDP/TCP/TLS and Smart; OpenVPN supplies UDP/TCP when
its service is installed. `protocol.set` accepts `{ "value": "<advertised-id>" }`,
requires a signed-in account and a disconnected tunnel, and persists the choice
without activating a connection. Missing engines are not advertised.

`features.vpn_accelerator.enabled` reports the persisted native preference.
`features.writes.vpn_accelerator` requires a signed-in paid account. `feature.set`
uses `feature="vpn_accelerator"` and a boolean `value`.

### Port forwarding

`features.port_forwarding.enabled` reports the persisted native preference.
For signed-in paid users, `feature.set` accepts `feature="port_forwarding"` with
a boolean `value`. While a P2P tunnel is active, `active_port` comes from the
Local Agent response and remains `null` until a forwarded port is observed.

### Anonymous crash reports

`features.anonymous_crash_reports.enabled` remains false and
`features.writes.anonymous_crash_reports` remains false. The native Rust agent
excludes automatic crash collection/upload by community-project scope and
does not expose a writable upload switch. Anonymous connection
statistics are a separate, explicit opt-in preference.
