#!/bin/bash
# ============================================================================
# PortScan Defender - Installation Script
# Debian 11+, Ubuntu 20.04+
# ============================================================================
set -euo pipefail

INSTALL_DIR="/opt/portscan-defender"
DATA_DIR="/var/lib/portscan-defender"
LOG_DIR="/var/log/portscan-defender"
SERVICE_NAME="portscan-defender"

if (( EUID != 0 )); then
    echo "Error: must run as root" >&2
    exit 1
fi

echo "=== PortScan Defender Installation ==="

# ---- 1) Dependencies ----
echo "[1/6] Installing dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    nftables jq procps iproute2 coreutils gawk

# ---- 2) Directories ----
echo "[2/6] Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

# ---- 3) Files ----
echo "[3/6] Installing application files..."
install -m 0755 portscan-defender.sh   "$INSTALL_DIR/portscan-defender.sh"
install -m 0644 portscan-defender.conf "$INSTALL_DIR/portscan-defender.conf"
install -m 0644 port_whitelist.txt     "$INSTALL_DIR/port_whitelist.txt"
install -m 0644 README.md              "$INSTALL_DIR/README.md" 2>/dev/null || true
sed -i 's/\r$//' "$INSTALL_DIR/portscan-defender.sh"
sed -i 's/\r$//' "$INSTALL_DIR/portscan-defender.conf"
sed -i 's/\r$//' "$INSTALL_DIR/port_whitelist.txt"
chmod 755 "$INSTALL_DIR/portscan-defender.sh"

# ---- 4) systemd unit ----
echo "[4/6] Installing systemd service..."
install -m 0644 portscan-defender.service "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload

# ---- 5) Enable & start ----
echo "[5/6] Enabling and starting service..."
systemctl enable "$SERVICE_NAME.service"
systemctl restart "$SERVICE_NAME.service"

# ---- 6) Verify ----
echo "[6/6] Verifying..."
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo
    echo "=== ✓ Installation complete ==="
else
    echo
    echo "=== ✗ Service failed to start. Recent logs: ==="
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
    exit 1
fi

cat <<EOF

Management commands:
  systemctl status $SERVICE_NAME
  systemctl restart $SERVICE_NAME
  journalctl -u $SERVICE_NAME -f

Inspection:
  $INSTALL_DIR/portscan-defender.sh --status
  $INSTALL_DIR/portscan-defender.sh --list
  $INSTALL_DIR/portscan-defender.sh --unblock 1.2.3.4

Config:
  $INSTALL_DIR/portscan-defender.conf
  $INSTALL_DIR/port_whitelist.txt

After editing config:
  systemctl reload $SERVICE_NAME      # for whitelist changes
  systemctl restart $SERVICE_NAME     # for detection threshold changes
EOF