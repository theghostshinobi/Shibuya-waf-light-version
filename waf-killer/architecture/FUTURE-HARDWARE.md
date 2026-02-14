# Future Hardware Roadmap: SmartNICs, DPUs, and FPGAs

## Strategy
As traffic scales beyond 100Gbps, CPU-based packet processing (even with eBPF) becomes a bottleneck. We must move valid traffic rules to network silicon.

## 1. NVIDIA BlueField (DPU)
**Target:** 200Gbps - 400Gbps
**Integration Path:**
- **DOCA Flow:** Use NVIDIA's DOCA SDK to offload flow matching and actions.
- **RegEx Offload:** Use BlueField's hardware regex engine for payload inspection (SQLi/XSS signatures) without CPU cost.
- **Implementation:** Rust `bindgen` wrapper around `libdoca`.

## 2. Intel IPU / Mount Evans
**Target:** Hyperscale Cloud Deployments
**Integration Path:**
- **P4 Programmability:** Write P4 programs for the IPU pipeline.
- **DPDK:** Use standardized DPDK polling drivers for high-speed packet access if P4 is too restrictive.

## 3. FPGAs (Xilinx Alveo)
**Target:** Ultra-Low Latency (<10µs)
**Integration Path:**
- Custom HDL/HLS logic for distinct "Security Blocks".
- **Shell:** Use standard shells (e.g., Corundum) and implement WAF logic as a plugin module.

## 4. P4 Tofino Switches
**Target:** Terabit Scale (ISP Level)
**Integration Path:**
- Compile DPAL IR to P4 tables.
- Push rules via P4Runtime to the switch ASIC.
- **Limitation:** Stateless only (mostly). Complex stateful tracking stays in Host/SmartNIC.

## Summary
The DPAL architecture ensures that when we write a driver for *one* of these, the entire WAF logic is instantly compatible. We do not rewrite the WAF; we only write the *backend driver*.
