use ark_ff::PrimeField;

use crate::bytecode::types::RuntimeAnalysis;
use crate::common::DeploymentData;

pub mod access;
pub mod constructor;
pub mod cross_contract_reentrancy;
pub mod defi_composability;
pub mod evm_state;
pub mod flash_loan;
pub mod front_running;
pub mod gas_limit;
pub mod gas_griefing;
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
pub mod test_circuit;
pub mod timestamp_dependency;
pub mod unchecked_calls;
pub mod upgrade;

// New EVM Circuit Modules for Full zkEVM Compliance
pub mod execution_trace;
pub mod stack_memory_circuit;
pub mod opcode_circuit;
pub mod complete_evm_circuit;

// Import for internal use
use access::AccessControlCircuit;
use constructor::ConstructorCircuit;
use cross_contract_reentrancy::CrossContractReentrancyCircuit;
use defi_composability::{DeFiComposabilityCircuit, EconomicSecurityCircuit};
use evm_state::EVMStateCircuit;
use front_running::FrontRunningCircuit;
use gas_limit::GasLimitCircuit;
use gas_griefing::GasGriefingCircuit;
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

// New EVM Circuit Imports
use execution_trace::{EVMExecutionTrace, ExecutionTraceResult, ExecutionPerformance};
use stack_memory_circuit::{StackMemoryVerifier, StackMemoryProof};
use opcode_circuit::{OpcodeValidationCircuit, OpcodeValidationProof};
pub use complete_evm_circuit::{CompleteEVMCircuit, CompleteEVMProof, EFComplianceAttestation};

// Re-export circuits for public use
pub use integer_overflow::IntegerOverflowCircuit;
pub use flash_loan::FlashLoanCircuit;
pub use test_circuit::TestCircuit;
pub use opcode_circuit::{ExecutionContext, BlockContext};
// CompleteEVMCircuit is already re-exported above

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
        UncheckedCallsCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
    
    /// Build gas griefing vulnerability detection circuit
    pub fn build_gas_griefing(&self) -> GasGriefingCircuit<F> {
        GasGriefingCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
    
    /// Build cross-contract reentrancy vulnerability detection circuit
    pub fn build_cross_contract_reentrancy(&self) -> CrossContractReentrancyCircuit<F> {
        CrossContractReentrancyCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
    
    /// Build DeFi composability security verification circuit
    pub fn build_defi_composability(
        &self,
        contracts: Vec<ethers::types::H160>,
        risks: Vec<crate::analysis::defi_composability::ComposabilityRisk>
    ) -> DeFiComposabilityCircuit<F> {
        DeFiComposabilityCircuit::new(
            self.deployment.clone(),
            self.runtime.clone(),
            contracts,
            risks,
        )
    }
    
    /// Build economic security verification circuit
    pub fn build_economic_security(
        &self,
        liquidity_depth: f64,
        collateralization_ratio: f64,
        value_at_risk: f64,
        max_extractable_value: f64,
        is_solvent_under_stress: bool,
    ) -> EconomicSecurityCircuit<F> {
        EconomicSecurityCircuit::new(
            liquidity_depth,
            collateralization_ratio,
            value_at_risk,
            max_extractable_value,
            is_solvent_under_stress,
        )
    }

    /// Build EVM execution trace circuit for opcode-level proving
    pub fn build_execution_trace(&self) -> EVMExecutionTrace {
        EVMExecutionTrace::new()
    }

    /// Build stack and memory verification circuit
    pub fn build_stack_memory_verifier(&self) -> StackMemoryVerifier {
        StackMemoryVerifier::new()
    }

    /// Build opcode validation circuit
    pub fn build_opcode_validation(&self) -> OpcodeValidationCircuit {
        OpcodeValidationCircuit::new()
    }

    /// Build complete EVM circuit with full EF compliance
    pub fn build_complete_evm_circuit(&self) -> CompleteEVMCircuit<F> {
        CompleteEVMCircuit::new(
            self.build_execution_trace(),
            self.build_stack_memory_verifier(),
            self.build_opcode_validation(),
            self.build_evm_state(),
            self.deployment.clone(),
            self.runtime.clone(),
        )
    }
}
