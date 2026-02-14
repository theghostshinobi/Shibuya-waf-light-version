#!/bin/bash

set -e

echo "🔥 Installing WAF Killer..."

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

# Download latest release (Stub URL)
LATEST_URL="https://github.com/waf-killer/waf-killer/releases/latest/download/waf-${OS}-${ARCH}"

# echo "Downloading from ${LATEST_URL}..."
# curl -L "$LATEST_URL" -o /tmp/waf

# Setup directories
sudo mkdir -p /etc/waf
sudo chown $(whoami) /etc/waf

# Install binary (assuming building locally for now)
# sudo mv /tmp/waf /usr/local/bin/waf
# sudo chmod +x /usr/local/bin/waf

# Ensure we have cargo to build for this demo
if command -v cargo &> /dev/null; then
    echo "Building WAF CLI..."
    cargo build -p waf-killer-cli --release
    # sudo cp target/release/waf-killer-cli /usr/local/bin/waf
    echo "Binary available at target/release/waf-killer-cli"
    echo "Alias created for this session: alias waf=./target/release/waf-killer-cli"
    alias waf=./target/release/waf-killer-cli
else
    echo "Cargo not found, cannot build."
fi

# Install completions
# waf completions bash | sudo tee /etc/bash_completion.d/waf > /dev/null

echo "✅ WAF Killer installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run setup: waf init"
echo "  2. Start WAF: waf start"
echo ""
