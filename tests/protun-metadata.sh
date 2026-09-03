#!/usr/bin/bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helper="$project_root/packaging/arch/proton-omarchy-protun-metadata"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
descriptor="$workdir/nm-protun.name"

cat >"$descriptor" <<'EOF'
supports-safe-private-file-access=true
[VPN Connection]
name=protun
service=org.freedesktop.NetworkManager.protun
program=/usr/libexec/nm-protun-service
supports-multiple-connections=false
SystemdService=nm-protun.service

[GNOME]
auth-dialog=/usr/libexec/nm-protun-auth-dialog
EOF

PROTON_OMARCHY_PROTUN_DESCRIPTOR="$descriptor" \
PROTON_OMARCHY_PROTUN_SKIP_RELOAD=1 \
  "$helper"

[[ $(grep -Fc 'supports-safe-private-file-access=true' "$descriptor") == 1 ]]
awk '
  /^\[VPN Connection\]$/ { in_vpn = 1; next }
  /^\[/ { in_vpn = 0 }
  in_vpn && /^supports-safe-private-file-access=true$/ { found++ }
  END { exit found == 1 ? 0 : 1 }
' "$descriptor"

before=$(sha256sum "$descriptor")
PROTON_OMARCHY_PROTUN_DESCRIPTOR="$descriptor" \
PROTON_OMARCHY_PROTUN_SKIP_RELOAD=1 \
  "$helper"
after=$(sha256sum "$descriptor")
[[ $before == "$after" ]]

printf 'protun metadata normalization: ok\n'
