# Data Plane Abstraction Layer (DPAL) Specification

## 1. Overview
The Data Plane Abstraction Layer (DPAL) is the contract that decouples the WAF's security decision logic (Control Plane) from the underlying packet processing engine (Data Plane).

This architecture allows "Write Once, Run Anywhere" policies. A security rule defined in the WAF core can be compiled and deployed to:
- **Fast Path:** XDP/eBPF (Kernel Space), SmartNICs (Hardware), FPGAs.
- **Slow Path:** User-space Rust Workers (Legacy/Complex Logic).

## 2. Core Concepts

### 2.1 The Intermediate Representation (IR)
All security policies (e.g., "Block IP 1.2.3.4", "Rate Limit /login to 5req/s") are compiled into an abstract Intermediate Representation (IR) before being sent to a backend.

**Key Goals of IR:**
- **Hardware Agnostic:** Does not contain BPF maps or P4 tables.
- **Serializable:** Can be sent over gRPC/Channels.
- **Verifiable:** Can be statically analyzed for conflicts.

### 2.2 Backend Capabilities
Not all backends are equal. The Control Plane must query the backend's capabilities before deploying a rule.

```rust
pub struct BackendCapabilities {
    pub max_rules: usize,
    pub supports_stateful_inspection: bool,
    pub supports_payload_inspection: bool, // e.g., SmartNIC regex
    pub offload_type: OffloadType,
}
```

### 2.3 The Contract
The `DataPlaneBackend` trait defines the operations any data plane must support.

```rust
pub trait DataPlaneBackend {
    fn name(&self) -> &str;
    fn capabilities(&self) -> BackendCapabilities;
    fn apply_policy(&mut self, policy: AbstractPolicy) -> Result<()>;
    fn remove_policy(&mut self, policy_id: PolicyId) -> Result<()>;
}
```

## 3. Rule Lifecycle

1.  **Creation:** Admin defines a rule (YAML/API).
2.  **Compilation:** WAF Core compiles rule to DPAL IR.
3.  **Selection:** Manager checks which backend can handle the rule (prefer Fast Path).
4.  **Translation:** Backend Driver translates IR to specific implementation (e.g., BPF Map Update, P4 Runtime entry).
5.  **Deployment:** Rule is pushed to the device/kernel.
6.  **Telemetry:** Device reports hits/drops back to Core asynchronously.

## 4. Telemetry Standard
Backends must report telemetry in a unified format:
- `timestamp`: u64 (nanoseconds)
- `policy_id`: u32
- `action_taken`: Allow/Drop/Redirect
- `src_ip`: IpAddr
- `metadata`: Key-Value pairs (optional)

## 5. Future Hardware Support
- **DPUs (NVIDIA BlueField):** Use DOCA SDK wrapped in a Rust DPAL Backend.
- **IPUs (Intel):** Use DPDK/SPDK via Rust FFI.
- **Switching ASICs:** P4 Runtime via a gRPC Backend.
