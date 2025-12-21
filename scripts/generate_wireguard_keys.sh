#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_ROOT/keys"

echo "WireGuard Key Generation Script"
echo "================================"
echo ""

if ! command -v wg &> /dev/null; then
    echo "Error: WireGuard (wg) is not installed."
    echo "Please install WireGuard first:"
    echo "  - Ubuntu/Debian: sudo apt install wireguard-tools"
    echo "  - macOS: brew install wireguard-tools"
    echo "  - Windows: Download from https://www.wireguard.com/install/"
    exit 1
fi

mkdir -p "$KEYS_DIR"

echo "Generating server keys..."
wg genkey | tee "$KEYS_DIR/server_private.key" | wg pubkey > "$KEYS_DIR/server_public.key"
echo "✓ Server keys generated"

echo "Generating peer (local LLM server) keys..."
wg genkey | tee "$KEYS_DIR/peer_private.key" | wg pubkey > "$KEYS_DIR/peer_public.key"
echo "✓ Peer keys generated"

chmod 600 "$KEYS_DIR"/*.key

echo ""
echo "Keys generated successfully!"
echo "================================"
echo ""
echo "Server Public Key:"
cat "$KEYS_DIR/server_public.key"
echo ""
echo "Peer Public Key:"
cat "$KEYS_DIR/peer_public.key"
echo ""
echo "================================"
echo ""
echo "Next steps:"
echo "1. Store keys in AWS Systems Manager Parameter Store:"
echo ""
echo "   aws ssm put-parameter --name private-key --type SecureString --value \"\$(cat $KEYS_DIR/server_private.key)\""
echo "   aws ssm put-parameter --name public-key --type String --value \"\$(cat $KEYS_DIR/server_public.key)\""
echo "   aws ssm put-parameter --name peer-public-key --type String --value \"\$(cat $KEYS_DIR/peer_public.key)\""
echo "   aws ssm put-parameter --name server-address --type String --value \"10.200.0.1/24\""
echo "   aws ssm put-parameter --name peer-address --type String --value \"10.200.0.2/32\""
echo "   aws ssm put-parameter --name peer-allowed-ips --type String --value \"10.200.0.2/32\""
echo ""
echo "2. Configure your local LLM server with the peer private key:"
echo "   Private Key: (see $KEYS_DIR/peer_private.key)"
echo ""
echo "WARNING: Keep these keys secure! The private keys should never be committed to version control."
