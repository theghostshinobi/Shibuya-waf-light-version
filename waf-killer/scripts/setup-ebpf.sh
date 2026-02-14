#!/bin/bash
# scripts/setup-ebpf.sh

echo "🚀 Setting up eBPF for WAF Killer..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (eBPF requires kernel access)"
    exit 1
fi

# Check kernel version (need 5.10+)
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
if (( $(echo "$KERNEL_VERSION < 5.10" | bc -l) )); then
    echo "❌ Kernel version 5.10+ required (current: $(uname -r))"
    exit 1
fi

echo "✅ Kernel version: $(uname -r)"

# Install dependencies
echo "📦 Installing dependencies..."

if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-$(uname -r) \
        build-essential
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS
    yum install -y \
        clang \
        llvm \
        libbpf-devel \
        kernel-devel
else
    echo "❌ Unsupported distribution"
    exit 1
fi

# Build eBPF programs
echo "🔨 Building eBPF programs..."
cd ebpf
make

if [ $? -ne 0 ]; then
    echo "❌ Failed to build eBPF programs"
    exit 1
fi

echo "✅ eBPF programs built successfully"

# Check network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "🌐 Detected network interface: $INTERFACE"

echo ""
echo "✅ eBPF setup complete!"
echo ""
echo "To run WAF with eBPF:"
echo "  export ENABLE_EBPF=true"
echo "  export NETWORK_INTERFACE=$INTERFACE"
echo "  sudo ./target/release/waf-killer"
echo ""
