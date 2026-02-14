use crate::dpal::ir::AbstractPolicy;
use crate::dpal::interface::{DataPlaneBackend, BackendCapabilities};
use anyhow::{Result, anyhow};

pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile_for_backend(
        policy: &AbstractPolicy, 
        backend: &dyn DataPlaneBackend
    ) -> Result<()> {
        let caps = backend.capabilities();
        
        // 1. Verify capabilities
        if !caps.supports_payload_inspection {
            // If policy requires payload inspection but backend doesn't support it...
            // Check if policy has payload conditions
            for cond in &policy.conditions {
               if let crate::dpal::ir::MatchCondition::HttpHeader { .. } = cond {
                   return Err(anyhow!("Backend {} does not support Payload Inspection needed for this policy", caps.name));
               }
            }
        }

        // 2. Real compilation logic would accept a specific visitor for the backend
        // For now, we just validate compatibility.
        
        Ok(())
    }
}
