use ark_ff::PrimeField;

use crate::bytecode::types::RuntimeAnalysis;
use crate::common::DeploymentData;

pub mod access;
pub mod constructor;
pub mod evm_state;
pub mod flash_loan;
pub mod front_running;
pub mod gas_limit;
pub mod governance;
pub mod integer_overflow;
pub mod mev;
pub mod memory;
pub mod oracle;
pub mod precision;
pub mod proxy;
pub mod reentrancy;
pub mod self_destruct;
pub mod signature_replay;
pub mod state;
pub mod storage;
pub mod timestamp_dependency;
pub mod unchecked_calls;
pub mod upgrade;

// Import for internal use
use access::AccessControlCircuit;
use constructor::ConstructorCircuit;
use evm_state::EVMStateCircuit;
use front_running::FrontRunningCircuit;
use gas_limit::GasLimitCircuit;
use governance::GovernanceCircuit;
use mev::MEVCircuit;
use memory::MemorySafetyCircuit;
use oracle::OracleCircuit;
use precision::PrecisionCircuit;
use proxy::ProxyCircuit;
use reentrancy::ReentrancyCircuit;
use self_destruct::SelfDestructCircuit;
use signature_replay::SignatureReplayCircuit;
use state::StateTransitionCircuit;
use storage::StorageCircuit;
use timestamp_dependency::TimestampDependencyCircuit;
use unchecked_calls::UncheckedCallsCircuit;
use upgrade::UpgradeVerificationCircuit;

// Re-export circuits for public use
pub use integer_overflow::IntegerOverflowCircuit;
pub use flash_loan::FlashLoanCircuit;

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

    /// Build oracle manipulation vulnerability detection circuit
    pub fn build_oracle(&self) -> OracleCircuit<F> {
        OracleCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build reentrancy vulnerability detection circuit
    pub fn build_reentrancy(&self) -> ReentrancyCircuit<F> {
        ReentrancyCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }

    /// Build upgrade verification circuit
    pub fn build_upgrade_verification(
        &self,
        new_deployment: DeploymentData,
    ) -> UpgradeVerificationCircuit<F> {
        UpgradeVerificationCircuit::new(
            self.deployment.clone(),
            new_deployment,
            self.runtime.clone(),
        )
    }
    
    /// Build integer overflow/underflow vulnerability detection circuit
    pub fn build_integer_overflow(&self) -> IntegerOverflowCircuit<F> {
        IntegerOverflowCircuit::new(self.deployment.clone(), self.runtime.clone())
    }
    
    /// Build flash loan vulnerability detection circuit
    pub fn build_flash_loan(&self) -> FlashLoanCircuit<F> {
        FlashLoanCircuit::new(self.deployment.clone(), self.runtime.clone())
    }
    
    /// Build signature replay vulnerability detection circuit
    pub fn build_signature_replay(&self) -> SignatureReplayCircuit<F> {
        SignatureReplayCircuit::new(self.deployment.clone(), self.runtime.clone())
    }
    
    /// Build proxy vulnerability detection circuit
    pub fn build_proxy(&self) -> ProxyCircuit<F> {
        ProxyCircuit::new(self.deployment.clone(), self.runtime.clone())
    }
    
    /// Build timestamp dependency vulnerability detection circuit
    pub fn build_timestamp_dependency(&self) -> TimestampDependencyCircuit<F> {
        TimestampDependencyCircuit::new(self.deployment.clone(), self.runtime.clone())
    }

    /// Build gas limit vulnerability detection circuit
    pub fn build_gas_limit(&self) -> GasLimitCircuit<F> {
        GasLimitCircuit::new(self.deployment.clone(), self.runtime.clone())
    }

    /// Build governance circuit
    pub fn build_governance(&self) -> GovernanceCircuit<F> {
        GovernanceCircuit::new(self.deployment.clone(), self.runtime.clone())
    }

    /// Build self-destruct vulnerability detection circuit
    pub fn build_self_destruct(&self) -> SelfDestructCircuit<F> {
        SelfDestructCircuit::new(self.deployment.clone(), self.runtime.clone())
    }

    /// Build unchecked calls vulnerability detection circuit
    pub fn build_unchecked_calls(&self) -> UncheckedCallsCircuit<F> {
        UncheckedCallsCircuit::new(self.deployment.clone(), self.runtime.clone())
    }
}
