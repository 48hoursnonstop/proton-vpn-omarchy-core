#!/usr/bin/bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helper="$project_root/packaging/arch/proton-omarchy-protun-metadata"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
descriptor="$workdir/nm-protun.name"
state_dir="$workdir/state"
original="$workdir/original"

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
cp "$descriptor" "$original"

run_helper() {
  PROTON_OMARCHY_PROTUN_DESCRIPTOR="$descriptor" \
  PROTON_OMARCHY_PROTUN_STATE_DIR="$state_dir" \
  PROTON_OMARCHY_PROTUN_SKIP_RELOAD=1 \
    "$helper" "$@"
}

run_helper
[[ $(grep -Fc 'supports-safe-private-file-access=true' "$descriptor") == 1 ]]
awk '
  /^\[VPN Connection\]$/ { in_vpn = 1; next }
  /^\[/ { in_vpn = 0 }
  in_vpn && /^supports-safe-private-file-access=true$/ { found++ }
  END { exit found == 1 ? 0 : 1 }
' "$descriptor"

before=$(sha256sum "$descriptor")
run_helper
after=$(sha256sum "$descriptor")
[[ $before == "$after" ]]

run_helper --restore
cmp -s "$descriptor" "$original"
[[ ! -e $state_dir ]]

# Adopt the exact untracked mutation made by v0.9.3 and make it reversible.
cat >"$descriptor" <<'EOF'
[VPN Connection]
name=protun
service=org.freedesktop.NetworkManager.protun
program=/usr/libexec/nm-protun-service
supports-multiple-connections=false
SystemdService=nm-protun.service

[GNOME]
auth-dialog=/usr/libexec/nm-protun-auth-dialog
EOF
cp "$descriptor" "$original"
run_helper
rm -rf -- "$state_dir"
expected_sha=$(sha256sum "$original" | awk '{ print $1 }')
PROTON_OMARCHY_PROTUN_EXPECTED_SHA256="$expected_sha" run_helper
[[ -f $state_dir/patched.sha256 ]]
run_helper --restore
cmp -s "$descriptor" "$original"

# An upstream descriptor that already declares support is not ours to track.
cat >"$descriptor" <<'EOF'
[VPN Connection]
name=protun
service=org.freedesktop.NetworkManager.protun
program=/usr/libexec/nm-protun-service
supports-multiple-connections=false
supports-safe-private-file-access=true
SystemdService=nm-protun.service
EOF
rm -rf -- "$state_dir"
upstream_sha=$(sha256sum "$descriptor" | awk '{ print $1 }')
PROTON_OMARCHY_PROTUN_EXPECTED_SHA256="$upstream_sha" run_helper
[[ ! -e $state_dir ]]

# Never overwrite a descriptor someone changed after our repair.
sed -i '/supports-safe-private-file-access=true/d' "$descriptor"
run_helper
printf '# later local change\n' >>"$descriptor"
changed_sha=$(sha256sum "$descriptor")
run_helper --restore
[[ $(sha256sum "$descriptor") == "$changed_sha" ]]

printf 'protun metadata normalization and rollback: ok\n'
