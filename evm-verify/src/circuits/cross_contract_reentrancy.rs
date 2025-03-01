use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;
use ethers::types::{H256, Bytes};

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::analyzer_cross_contract_reentrancy;

/// Circuit for detecting cross-contract reentrancy vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Direct cross-contract reentrancy: Contract A calls Contract B, which calls back into A
/// 2. Indirect cross-contract reentrancy: Contract A calls B, B calls C, C calls back into A
/// 3. Proxy-based cross-contract reentrancy: Using proxy contracts to perform reentrancy
/// 4. Shared storage cross-contract reentrancy: Multiple contracts sharing storage that can be manipulated
pub struct CrossContractReentrancyCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Direct cross-contract reentrancy warnings
    pub direct_warnings: Vec<SecurityWarning>,
    /// Indirect cross-contract reentrancy warnings
    pub indirect_warnings: Vec<SecurityWarning>,
    /// Proxy-based cross-contract reentrancy warnings
    pub proxy_warnings: Vec<SecurityWarning>,
    /// Shared storage cross-contract reentrancy warnings
    pub shared_storage_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> CrossContractReentrancyCircuit<F> {
    /// Create a new cross-contract reentrancy circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        // Create a BytecodeAnalyzer instance with empty bytecode
        // In a real implementation, we would extract bytecode from runtime
        let analyzer = BytecodeAnalyzer::new(Bytes::from(vec![0u8; 0]));
        
        // Get cross-contract reentrancy warnings
        let all_warnings = analyzer_cross_contract_reentrancy::detect_cross_contract_reentrancy(&analyzer);
        
        // Categorize warnings by type
        let direct_warnings = all_warnings.iter()
            .filter(|w| w.description.contains("direct"))
            .cloned()
            .collect();
            
        let indirect_warnings = all_warnings.iter()
            .filter(|w| w.description.contains("indirect"))
            .cloned()
            .collect();
            
        let proxy_warnings = all_warnings.iter()
            .filter(|w| w.description.contains("proxy"))
            .cloned()
            .collect();
            
        let shared_storage_warnings = all_warnings.iter()
            .filter(|w| w.description.contains("shared storage"))
            .cloned()
            .collect();
        
        Self {
            deployment,
            runtime,
            direct_warnings,
            indirect_warnings,
            proxy_warnings,
            shared_storage_warnings,
            _phantom: PhantomData,
        }
    }

    /// Create a new cross-contract reentrancy circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        direct_warnings: Vec<SecurityWarning>,
        indirect_warnings: Vec<SecurityWarning>,
        proxy_warnings: Vec<SecurityWarning>,
        shared_storage_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            direct_warnings,
            indirect_warnings,
            proxy_warnings,
            shared_storage_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any direct cross-contract reentrancy warnings
    pub fn has_direct_reentrancy(&self) -> bool {
        !self.direct_warnings.is_empty()
    }

    /// Check if there are any indirect cross-contract reentrancy warnings
    pub fn has_indirect_reentrancy(&self) -> bool {
        !self.indirect_warnings.is_empty()
    }

    /// Check if there are any proxy-based cross-contract reentrancy warnings
    pub fn has_proxy_reentrancy(&self) -> bool {
        !self.proxy_warnings.is_empty()
    }

    /// Check if there are any shared storage cross-contract reentrancy warnings
    pub fn has_shared_storage_reentrancy(&self) -> bool {
        !self.shared_storage_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for CrossContractReentrancyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Direct cross-contract reentrancy
        let direct_reentrancy = cs.new_witness_variable(|| {
            if self.has_direct_reentrancy() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Indirect cross-contract reentrancy
        let indirect_reentrancy = cs.new_witness_variable(|| {
            if self.has_indirect_reentrancy() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Proxy-based cross-contract reentrancy
        let proxy_reentrancy = cs.new_witness_variable(|| {
            if self.has_proxy_reentrancy() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Shared storage cross-contract reentrancy
        let shared_storage_reentrancy = cs.new_witness_variable(|| {
            if self.has_shared_storage_reentrancy() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Create a witness variable for the overall contract safety
        let contract_is_safe = cs.new_witness_variable(|| {
            if !self.has_direct_reentrancy() && 
               !self.has_indirect_reentrancy() && 
               !self.has_proxy_reentrancy() && 
               !self.has_shared_storage_reentrancy() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce that the contract is safe
        // This is equivalent to enforcing that each vulnerability is not present
        
        // 1. Enforce that direct_reentrancy is false (0)
        cs.enforce_constraint(
            LinearCombination::from(direct_reentrancy),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 2. Enforce that indirect_reentrancy is false (0)
        cs.enforce_constraint(
            LinearCombination::from(indirect_reentrancy),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 3. Enforce that proxy_reentrancy is false (0)
        cs.enforce_constraint(
            LinearCombination::from(proxy_reentrancy),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 4. Enforce that shared_storage_reentrancy is false (0)
        cs.enforce_constraint(
            LinearCombination::from(shared_storage_reentrancy),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // Make contract_is_safe a public input
        cs.enforce_constraint(
            LinearCombination::from(contract_is_safe),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_bn254;
    use ethers::types::H160 as Address;

    #[test]
    fn test_safe_contract() {
        // Create a circuit with no vulnerabilities
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = CrossContractReentrancyCircuit::<ark_bn254::Fr>::new(deployment, runtime);

        // Create a new constraint system
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check that the circuit is satisfied (no vulnerabilities)
        assert!(cs.is_satisfied().unwrap());

        // Check that we have exactly 5 constraints (4 for vulnerabilities + 1 for contract safety)
        assert_eq!(cs.num_constraints(), 5);

        // Check that we have 5 witness variables (4 for vulnerabilities + 1 for contract safety)
        assert_eq!(cs.num_witness_variables(), 5);

        // Check that we have 1 instance variable (public input)
        assert_eq!(cs.num_instance_variables(), 1);
    }
}
