# Fast Path vs. Slow Path Design

## Philosophy
"Do as much as possible in hardware/kernel. Do complex logic in user-space only when necessary."

## The Hierarchy of Speed
1.  **Hardware Offload (ASIC/FPGA/SmartNIC):** 0% CPU Load. Line-rate.
2.  **Kernel Fast Path (XDP/eBPF):** Minimal CPU Load. Interrupt context.
3.  **Kernel Slow Path (TC/Netfilter):** Moderate CPU Load. Skb allocation.
4.  **User Space (Rust Worker):** High CPU Load. Context switches.

## Decision Matrix

| Feature | Execution Target | Rationale |
| :--- | :--- | :--- |
| **L3/L4 Drops (IP, Port)** | **Hardware / XDP** | Stateless, simple match. Perfect for TCAM/Hash tables. |
| **DDoS Mitigation (SYN Cookies)** | **XDP** | Needs state but simple logic. XDP is ideal. |
| **Rate Limiting (Token Bucket)** | **XDP / Hardware** | Simple atomic counters. Can be offloaded. |
| **Geo-Blocking** | **XDP** | Large map lookups, fast in eBPF. |
| **HTTP Header Patterns (Regex)** | **User Space / SmartNIC** | eBPF has no loops/string processing. DPU can offload this; standard NICs cannot. |
| **Payload Inspection (WAF Rules)** | **User Space** | Complex parsing (JSON/Multipart). Too heavy for kernel. |
| **ML Inference (Anomaly Detection)** | **User Space (GPU)** | requires matrix math. Impossible in kernel. |
| **User Authentication (JWT)** | **User Space** | Crypto operations are expensive/restricted in kernel. |

## Flow Promotion/Demotion
1.  **Optimistic Fast Path:** The Control Plane tries to push *every* new rule to the lowest layer (Hardware).
2.  **Capability Check:** If Hardware rejects it (e.g., "I don't support Regex"), it falls back to XDP.
3.  **Fallback:** If XDP rejects it (e.g., "Too complex"), it stays in User Space.

## Connection Splicing
For valid flows (e.g., authorized large file download), the User Space engine can "splice" the connection in the kernel (using eBPF `bpf_redirect_map`), effectively moving an established connection from Slow Path to Fast Path after inspection is done.
