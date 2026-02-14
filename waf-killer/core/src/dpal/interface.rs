use crate::dpal::ir::AbstractPolicy;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffloadType {
    None,       // Pure User Space
    KernelXDP,  // eBPF / XDP
    SmartNIC,   // DPU / FPGA
}

#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    pub name: String,
    pub max_rules: usize,
    pub supports_stateful_inspection: bool,
    pub supports_payload_inspection: bool,
    pub offload_type: OffloadType,
}

/// The contract that ANY Data Plane must satisfy
pub trait DataPlaneBackend: Send + Sync {
    /// Initial setup of the backend (e.g. attaching XDP programs)
    fn init(&mut self) -> Result<()>;

    /// Returns what this backend can do
    fn capabilities(&self) -> BackendCapabilities;

    /// Apply a security policy
    fn apply_policy(&mut self, policy: AbstractPolicy) -> Result<()>;

    /// Remove a security policy
    fn remove_policy(&mut self, policy_id: &str) -> Result<()>;
    
    /// Flushes all rules
    fn flush(&mut self) -> Result<()>;
}
