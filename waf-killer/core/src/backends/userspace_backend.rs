use crate::dpal::interface::{DataPlaneBackend, BackendCapabilities, OffloadType};
use crate::dpal::ir::AbstractPolicy;
use anyhow::Result;

pub struct UserspaceBackend;

impl UserspaceBackend {
    pub fn new() -> Self {
        Self {}
    }
}

impl DataPlaneBackend for UserspaceBackend {
    fn init(&mut self) -> Result<()> {
        println!("DPAL: Initializing Userspace Backend");
        Ok(())
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "Rust/UserSpace".to_string(),
            max_rules: 1_000_000, 
            supports_stateful_inspection: true, 
            supports_payload_inspection: true, 
            offload_type: OffloadType::None,
        }
    }

    fn apply_policy(&mut self, policy: AbstractPolicy) -> Result<()> {
        println!("DPAL [UserSpace]: Optimizing Policy ID {} for Rust execution...", policy.id);
        Ok(())
    }

    fn remove_policy(&mut self, policy_id: &str) -> Result<()> {
        println!("DPAL [UserSpace]: Removing Policy ID {}...", policy_id);
        Ok(())
    }
    
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
