#!/bin/bash


set -e

if [[ $(uname -s) != Linux ]]; then
    echo "This script only supports Linux with systemd."
    exit 1
fi

if ! command -v systemctl >/dev/null; then
    echo "Systemd is not available on this system."
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_DIR="$ROOT_DIR/did-api-gateway"
VENDOR_DIR="$ROOT_DIR/did-api-vendor/backend"
USER_NAME=${SUDO_USER:-$(whoami)}

install_service() {
    local name=$1
    local dir=$2
    local template="$ROOT_DIR/systemd/$name.service"
    local dest="/etc/systemd/system/$name.service"

    echo "\nInstalling $name.service to $dest"
    sudo sed -e "s|{{WORKING_DIR}}|$dir|g" -e "s|{{USER}}|$USER_NAME|g" \
        "$template" | sudo tee "$dest" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable "$name.service"
    sudo systemctl start "$name.service"
    echo "$name.service enabled and started"
}

read -p "Install systemd service for DID API Gateway? [y/N] " ans
if [[ $ans =~ ^[Yy]$ ]]; then
    install_service "did-api-gateway" "$GATEWAY_DIR"
fi

read -p "Install systemd service for DID API Vendor? [y/N] " ans
if [[ $ans =~ ^[Yy]$ ]]; then
    install_service "did-api-vendor" "$VENDOR_DIR"
fi

echo "Done."
