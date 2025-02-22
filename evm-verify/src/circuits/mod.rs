use ark_ff::PrimeField;

use crate::bytecode::types::RuntimeAnalysis;
use crate::common::DeploymentData;

pub mod access;
pub mod constructor;
pub mod memory;
pub mod state;
pub mod storage;

use access::AccessControlCircuit;
use constructor::ConstructorCircuit;
use memory::MemorySafetyCircuit;
use state::StateTransitionCircuit;
use storage::StorageCircuit;

/// Circuit builder
pub struct CircuitBuilder<F: PrimeField> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Phantom data
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CircuitBuilder<F> {
    /// Create new circuit builder
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Build access control circuit
    pub fn build_access_control(&self) -> AccessControlCircuit<F> {
        AccessControlCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build constructor circuit
    pub fn build_constructor(&self) -> ConstructorCircuit<F> {
        ConstructorCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build memory safety circuit
    pub fn build_memory_safety(&self) -> MemorySafetyCircuit<F> {
        MemorySafetyCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build state transition circuit
    pub fn build_state_transition(&self) -> StateTransitionCircuit<F> {
        StateTransitionCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build storage circuit
    pub fn build_storage(&self) -> StorageCircuit<F> {
        StorageCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
}
