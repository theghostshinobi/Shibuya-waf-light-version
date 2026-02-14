# Platform Support Guide

## Overview

Shibuya (WAF Killer) is designed to be cross-platform, running on Linux, macOS, and Windows. However, to achieve maximum performance and security depth, certain features utilize operating system specific capabilities.

The primary OS-specific feature is **eBPF (Extended Berkeley Packet Filter) XDP (eXpress Data Path)** high-performance packet filtering, which is exclusive to Linux.

## Feature Matrix

| Feature | Linux | macOS | Windows | Notes |
|---------|-------|-------|---------|-------|
| **Core WAF Proxy** | ✅ Supported | ✅ Supported | ✅ Supported | Full traffic inspection and blocking in userspace. |
| **ML Engine** | ✅ Supported | ✅ Supported | ✅ Supported | ONNX Runtime works on all major platforms. |
| **Threat Intel** | ✅ Supported | ✅ Supported | ✅ Supported | API and implementation are platform-agnostic. |
| **eBPF XDP Filter** | ✅ Supported | ❌ No | ❌ No | **Linux Kernel 5.10+ required**. Uses kernel-level drop for DDoS protection/IP bans. |

## eBPF XDP Support

### Linux (Supported)
On Linux systems with Kernel 5.10 or newer, Shibuya can load an eBPF program into the network driver (XDP hook). This allows it to drop malicious packets from blacklisted IPs *before* they reach the userspace application, providing:
- **DDoS mitigation** at line rate.
- **Microsecond latency** for blocked traffic.
- **Zero CPU overhead** for the main WAF process for blocked traffic.

**Requirements:**
- Kernel 5.10+
- `CAP_NET_ADMIN` and `CAP_BPF` capabilities (usually requires root).
- `linux-headers` installed for CO-RE (Compile Once – Run Everywhere) if compiling from source.

### macOS & Windows (Unsupported)
On non-Linux platforms, Shibuya transparently falls back to **Userspace Filtering**.
- The `BlockingAction` logic remains identical.
- IPs blocked by Threat Intel or Rate Limiting are dropped by the application layer.
- **Security Impact:** None. All attacks are still blocked.
- **Performance Impact:** Higher CPU usage during massive DDoS attacks compared to XDP, as packets must be copied to userspace before dropping.

### How to Check Support
Run the following command to check if your current environment supports eBPF acceleration:

```bash
waf check-ebpf
```

## deployment Recommendations

- **Development/Testing:** macOS/Windows are fully supported dev environments. The lack of eBPF does not affect functional testing of rules, ML, or API security.
- **Production (Low/Medium Traffic):** Userspace filtering is sufficient for most deployments under 10k RPS.
- **Production (High Traffic/Anti-DDoS):** Deployment on Linux is **strongly recommended** to leverage XDP/eBPF.
