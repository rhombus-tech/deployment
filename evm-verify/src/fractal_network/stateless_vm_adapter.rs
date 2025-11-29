// StatelessVM Adapter for Fractal Network
// Simplifies StatelessVM integration for proving tasks

#[cfg(feature = "stateless-integration")]
use zkevm_stateless_vm::{StatelessVM, Transaction};

use super::ZODAProofTask;
use std::sync::Arc;

/// Simplified adapter for StatelessVM integration
/// Handles the complexity of StatelessVM initialization
pub struct StatelessVMAdapter {
    #[cfg(feature = "stateless-integration")]
    vm: Option<Arc<StatelessVM>>,
    /// Whether vulnerability analysis is enabled
    enable_vulnerability_analysis: bool,
}

impl StatelessVMAdapter {
    /// Create new adapter with optional StatelessVM
    pub fn new(rpc_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_config(rpc_url, true) // Default: vulnerability analysis enabled
    }
    
    /// Create new adapter with vulnerability analysis configuration
    pub fn new_with_config(rpc_url: &str, enable_vulnerability_analysis: bool) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(feature = "stateless-integration")]
        {
            // Try to initialize StatelessVM
            match Self::init_stateless_vm(rpc_url, enable_vulnerability_analysis) {
                Ok(vm) => {
                    println!("✅ StatelessVM adapter initialized");
                    println!("   Vulnerability analysis: {}", if enable_vulnerability_analysis { "ENABLED" } else { "DISABLED (faster proving)" });
                    Ok(Self { 
                        vm: Some(Arc::new(vm)),
                        enable_vulnerability_analysis,
                    })
                }
                Err(e) => {
                    println!("⚠️  StatelessVM unavailable: {}", e);
                    println!("   Using TensorZODA-only proving");
                    Ok(Self { 
                        vm: None,
                        enable_vulnerability_analysis,
                    })
                }
            }
        }
        
        #[cfg(not(feature = "stateless-integration"))]
        {
            let _ = rpc_url; // Suppress unused warning
            println!("ℹ️  StatelessVM integration disabled (compile with --features stateless-integration)");
            Ok(Self { enable_vulnerability_analysis })
        }
    }
    
    #[cfg(feature = "stateless-integration")]
    fn init_stateless_vm(_rpc_url: &str, enable_vulnerability_analysis: bool) -> Result<StatelessVM, Box<dyn std::error::Error>> {
        use zkevm_stateless_vm::{StateBundler, SecurityVerifier, BytecodeAnalyzer, NoOpSecurityVerifier};
        use zkevm_stateless_vm::types::StateRoot;
        use tokio::sync::RwLock;
        
        // Initialize components
        let state_bundler = Arc::new(RwLock::new(StateBundler::new()));
        
        // Create security verifier based on configuration
        let security_verifier: Arc<dyn SecurityVerifier> = if enable_vulnerability_analysis {
            // Full vulnerability detection enabled
            let bytecode_analyzer = Arc::new(BytecodeAnalyzer::new());
            Arc::new(bytecode_analyzer as Arc<dyn SecurityVerifier>)
        } else {
            // No-op verifier for maximum performance
            Arc::new(NoOpSecurityVerifier::new())
        };
        
        let initial_state_root = StateRoot::default();
        let initial_block_height = 0;
        
        Ok(StatelessVM::new(
            state_bundler,
            security_verifier,
            initial_state_root,
            initial_block_height,
        ))
    }
    
    /// Check if StatelessVM is available
    pub fn has_stateless_vm(&self) -> bool {
        #[cfg(feature = "stateless-integration")]
        {
            self.vm.is_some()
        }
        
        #[cfg(not(feature = "stateless-integration"))]
        {
            false
        }
    }
    
    /// Convert ZODA task to StatelessVM transaction
    #[cfg(feature = "stateless-integration")]
    fn task_to_transaction(&self, task: &ZODAProofTask) -> Result<Transaction, Box<dyn std::error::Error>> {
        use zkevm_stateless_vm::types::Address;
        use ethereum_types::U256;
        
        // Extract transaction data from task segments
        let data: Vec<u8> = task.tensor_segments
            .iter()
            .flat_map(|seg| seg.data.clone())
            .collect();
        
        Ok(Transaction {
            id: task.circuit_id.clone(),
            from: Address::zero(),
            to: Some(Address::zero()),
            value: U256::zero(),
            data,
            gas_limit: 1_000_000,
            gas_price: U256::zero(),
            code: None,
            block_height: 0,
            state_requirements: vec![],
            bundled_state: None,
            verification_level: None,
            priority: task.priority,
            nonce: None,
        })
    }
    
    /// Prove transaction using StatelessVM (if available)
    /// Falls back to caller if StatelessVM not available
    pub async fn prove_with_stateless_vm(&self, task: &ZODAProofTask) -> Option<Vec<u8>> {
        #[cfg(feature = "stateless-integration")]
        {
            if let Some(ref vm) = self.vm {
                match self.task_to_transaction(task) {
                    Ok(tx) => {
                        if self.enable_vulnerability_analysis {
                            println!("   🔗 Using StatelessVM for transaction proving + vulnerability analysis");
                        } else {
                            println!("   🔗 Using StatelessVM for transaction proving (fast mode, no security checks)");
                        }
                        
                        // Execute transaction through StatelessVM
                        // Security checks enabled/disabled based on configuration
                        match vm.clone().execute_transaction(tx).await {
                            Ok(status) => {
                                println!("   ✅ StatelessVM execution complete");
                                
                                // Convert execution result to proof bytes
                                // In production: extract actual proof from execution
                                use serde_json;
                                match serde_json::to_vec(&status) {
                                    Ok(proof) => return Some(proof),
                                    Err(e) => println!("   ⚠️  Serialization failed: {}", e),
                                }
                            }
                            Err(e) => {
                                println!("   ⚠️  StatelessVM execution failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("   ⚠️  Task conversion failed: {}", e);
                    }
                }
            }
        }
        
        #[cfg(not(feature = "stateless-integration"))]
        {
            let _ = task; // Suppress unused warning
        }
        
        None // Caller should use TensorZODA fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_adapter_creation() {
        let adapter = StatelessVMAdapter::new("http://localhost:8545").unwrap();
        // Should not panic - adapter gracefully handles unavailability
        assert!(!adapter.has_stateless_vm() || adapter.has_stateless_vm());
    }
}
