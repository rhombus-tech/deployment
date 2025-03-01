use ark_ff::PrimeField;

use crate::bytecode::types::RuntimeAnalysis;
use crate::common::DeploymentData;

pub mod access;
pub mod constructor;
pub mod evm_state;
pub mod front_running;
pub mod mev;
pub mod memory;
pub mod precision;
pub mod state;
pub mod storage;
pub mod upgrade;

use access::AccessControlCircuit;
use constructor::ConstructorCircuit;
use evm_state::EVMStateCircuit;
use front_running::FrontRunningCircuit;
use mev::MEVCircuit;
use memory::MemorySafetyCircuit;
use precision::PrecisionCircuit;
use state::StateTransitionCircuit;
use storage::StorageCircuit;
use upgrade::UpgradeVerificationCircuit;

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

    /// Build EVM state circuit
    pub fn build_evm_state(&self) -> EVMStateCircuit<F> {
        EVMStateCircuit::new(
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

    /// Build front-running circuit
    pub fn build_front_running(&self) -> FrontRunningCircuit<F> {
        FrontRunningCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build MEV vulnerability detection circuit
    pub fn build_mev(&self) -> MEVCircuit<F> {
        MEVCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
    
    /// Build precision vulnerability detection circuit
    pub fn build_precision(&self) -> PrecisionCircuit<F> {
        PrecisionCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build upgrade verification circuit
    pub fn build_upgrade_verification(&self, new_deployment: DeploymentData) -> UpgradeVerificationCircuit<F> {
        UpgradeVerificationCircuit::new(
            self.deployment.clone(),
            new_deployment,
            self.runtime.clone(),
        )
    }
}
