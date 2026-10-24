#!/usr/bin/env bash
# Build multi-vpn-manager_<version>_all.deb from the repository.
#   packaging/build-deb.sh [VERSION] [OUTDIR]
# VERSION defaults to the VERSION constant in mvm.py. Output defaults to ./dist.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG=multi-vpn-manager
VERSION="${1:-$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$ROOT/mvm.py" | head -n1)}"
OUT="${2:-$ROOT/dist}"
[ -n "$VERSION" ] || { echo "could not determine version" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PAYLOAD="$STAGE/payload"

install -d "$PAYLOAD/DEBIAN" \
           "$PAYLOAD/usr/lib/$PKG" \
           "$PAYLOAD/usr/bin" \
           "$PAYLOAD/usr/share/applications" \
           "$PAYLOAD/usr/share/icons/hicolor/scalable/apps" \
           "$PAYLOAD/usr/share/doc/$PKG"

install -m 0644 "$ROOT/mvm.py" "$PAYLOAD/usr/lib/$PKG/mvm.py"
install -m 0644 "$ROOT/mvm.svg" "$PAYLOAD/usr/lib/$PKG/mvm.svg"
install -m 0644 "$ROOT/mvm.svg" "$PAYLOAD/usr/share/icons/hicolor/scalable/apps/$PKG.svg"
install -m 0644 "$ROOT/README.md" "$PAYLOAD/usr/share/doc/$PKG/README.md"

cat > "$PAYLOAD/usr/bin/mvm" <<'SH'
#!/bin/sh
exec python3 /usr/lib/multi-vpn-manager/mvm.py "$@"
SH
chmod 0755 "$PAYLOAD/usr/bin/mvm"

cat > "$PAYLOAD/usr/share/applications/$PKG.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Multi-VPN Manager
GenericName=VPN control center
Comment=Split-tunnel NetworkManager VPNs + sshuttle
Icon=multi-vpn-manager
Exec=gnome-terminal --title="Multi-VPN Manager" --geometry=170x48 -- mvm --colors truecolor
Terminal=false
Categories=Network;
Keywords=vpn;openvpn;l2tp;sshuttle;routes;network;
StartupNotify=true
Actions=doctor;status;

[Desktop Action doctor]
Name=Troubleshoot (deep doctor)
Exec=gnome-terminal --title="mvm doctor" --geometry=170x48 -- mvm --pause doctor --deep

[Desktop Action status]
Name=Status
Exec=gnome-terminal --title="mvm status" --geometry=170x48 -- mvm status --watch
DESKTOP

INSTALLED_KB="$(du -sk "$PAYLOAD" | cut -f1)"
cat > "$PAYLOAD/DEBIAN/control" <<CONTROL
Package: $PKG
Version: $VERSION
Architecture: all
Maintainer: Amir Aghighi <a.aghighi@paystar.team>
Installed-Size: $INSTALLED_KB
Depends: python3 (>= 3.10), network-manager, python3-venv
Recommends: sshuttle, libnotify-bin, network-manager-l2tp, network-manager-openvpn
Section: net
Priority: optional
Homepage: https://github.com/AmirAghighi02/multi-vpn-manager
Description: split-tunnel VPN control center (NetworkManager VPNs + sshuttle)
 A terminal UI and CLI that brings up NetworkManager VPNs (OpenVPN, L2TP/IPsec,
 WireGuard) and sshuttle tunnels, routing only the listed IPs/CIDRs/hostnames
 through each one. A VPN never becomes the default route.
 Run "mvm" to start the TUI; on first run it offers to install textual and rich into
 per-user data in ~/.local/share/multi-vpn-manager (MVM_HOME overrides).
CONTROL

install -d "$OUT"
DEB="$OUT/${PKG}_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PAYLOAD" "$DEB" >/dev/null
echo "$DEB"
