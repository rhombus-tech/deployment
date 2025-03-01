use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;

/// Circuit for detecting unchecked call vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Unchecked external call: External calls without checking the return value
/// 2. Unchecked low-level call: Low-level calls (call, delegatecall, staticcall) without checking return value
/// 3. Unchecked send/transfer: Send/transfer operations without checking success
/// 4. Missing revert on failure: Calls that don't revert on failure
pub struct UncheckedCallsCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Unchecked external call warnings
    pub unchecked_external_call_warnings: Vec<SecurityWarning>,
    /// Unchecked low-level call warnings
    pub unchecked_low_level_call_warnings: Vec<SecurityWarning>,
    /// Unchecked send/transfer warnings
    pub unchecked_send_transfer_warnings: Vec<SecurityWarning>,
    /// Missing revert on failure warnings
    pub missing_revert_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> UncheckedCallsCircuit<F> {
    /// Create a new unchecked calls circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            unchecked_external_call_warnings: Vec::new(),
            unchecked_low_level_call_warnings: Vec::new(),
            unchecked_send_transfer_warnings: Vec::new(),
            missing_revert_warnings: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new unchecked calls circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        unchecked_external_call_warnings: Vec<SecurityWarning>,
        unchecked_low_level_call_warnings: Vec<SecurityWarning>,
        unchecked_send_transfer_warnings: Vec<SecurityWarning>,
        missing_revert_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            unchecked_external_call_warnings,
            unchecked_low_level_call_warnings,
            unchecked_send_transfer_warnings,
            missing_revert_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any unchecked external call warnings
    pub fn has_unchecked_external_calls(&self) -> bool {
        !self.unchecked_external_call_warnings.is_empty()
    }

    /// Check if there are any unchecked low-level call warnings
    pub fn has_unchecked_low_level_calls(&self) -> bool {
        !self.unchecked_low_level_call_warnings.is_empty()
    }

    /// Check if there are any unchecked send/transfer warnings
    pub fn has_unchecked_send_transfer(&self) -> bool {
        !self.unchecked_send_transfer_warnings.is_empty()
    }

    /// Check if there are any missing revert on failure warnings
    pub fn has_missing_revert(&self) -> bool {
        !self.missing_revert_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for UncheckedCallsCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Unchecked external calls
        let unchecked_external_calls = cs.new_witness_variable(|| {
            if self.has_unchecked_external_calls() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Unchecked low-level calls
        let unchecked_low_level_calls = cs.new_witness_variable(|| {
            if self.has_unchecked_low_level_calls() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Unchecked send/transfer
        let unchecked_send_transfer = cs.new_witness_variable(|| {
            if self.has_unchecked_send_transfer() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Missing revert on failure
        let missing_revert = cs.new_witness_variable(|| {
            if self.has_missing_revert() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 5. Overall contract safety status
        let contract_vulnerable = cs.new_witness_variable(|| {
            if self.has_unchecked_external_calls() 
                || self.has_unchecked_low_level_calls()
                || self.has_unchecked_send_transfer()
                || self.has_missing_revert() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce constraints for each vulnerability type
        // 1. Enforce unchecked_external_calls == 0
        cs.enforce_constraint(
            LinearCombination::from(unchecked_external_calls),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 2. Enforce unchecked_low_level_calls == 0
        cs.enforce_constraint(
            LinearCombination::from(unchecked_low_level_calls),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 3. Enforce unchecked_send_transfer == 0
        cs.enforce_constraint(
            LinearCombination::from(unchecked_send_transfer),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 4. Enforce missing_revert == 0
        cs.enforce_constraint(
            LinearCombination::from(missing_revert),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ethers::types::{H256, U256};
    use crate::bytecode::security::{Operation, SecuritySeverity};

    // Helper function to create a mock deployment
    fn create_mock_deployment() -> DeploymentData {
        DeploymentData {
            owner: ethers::types::H160::zero(),
        }
    }

    // Helper function to create a mock runtime analysis
    fn create_mock_runtime() -> RuntimeAnalysis {
        RuntimeAnalysis::default()
    }

    // Helper function to create an unchecked external call warning
    fn create_unchecked_external_call_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UncheckedExternalCall,
            SecuritySeverity::Medium,
            0,
            "Unchecked external call detected".to_string(),
            vec![Operation::ExternalCall {
                target: H256::zero(),
                value: U256::zero(),
                data: vec![],
            }],
            "Always check the return value of external calls to handle potential failures".to_string(),
        )
    }

    // Helper function to create an unchecked low-level call warning
    fn create_unchecked_low_level_call_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UncheckedCallReturn,
            SecuritySeverity::Medium,
            0,
            "Unchecked low-level call detected".to_string(),
            vec![Operation::ExternalCall {
                target: H256::zero(),
                value: U256::zero(),
                data: vec![],
            }],
            "Always check the return value of low-level calls to handle potential failures".to_string(),
        )
    }

    // Helper function to create an unchecked send/transfer warning
    fn create_unchecked_send_transfer_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UncheckedCallReturn,
            SecuritySeverity::Medium,
            0,
            "Unchecked send/transfer detected".to_string(),
            vec![Operation::ValueCall {
                target: H256::zero(),
                value: U256::from(1),
            }],
            "Always check the return value of send/transfer operations to handle potential failures".to_string(),
        )
    }

    // Helper function to create a missing revert on failure warning
    fn create_missing_revert_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UncheckedCallReturn,
            SecuritySeverity::Medium,
            0,
            "Missing revert on call failure detected".to_string(),
            vec![Operation::ExternalCall {
                target: H256::zero(),
                value: U256::zero(),
                data: vec![],
            }],
            "Always revert the transaction if an external call fails to prevent partial execution".to_string(),
        )
    }

    #[test]
    fn test_safe_contract() {
        // Create a circuit with no vulnerabilities
        let circuit = UncheckedCallsCircuit::<Fr>::new(
            create_mock_deployment(),
            create_mock_runtime(),
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is satisfied
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }

    #[test]
    fn test_unchecked_external_calls() {
        // Create a circuit with unchecked external call vulnerability
        let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![create_unchecked_external_call_warning()],
            vec![],
            vec![],
            vec![],
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is not satisfied
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }

    #[test]
    fn test_unchecked_low_level_calls() {
        // Create a circuit with unchecked low-level call vulnerability
        let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![create_unchecked_low_level_call_warning()],
            vec![],
            vec![],
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is not satisfied
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }

    #[test]
    fn test_unchecked_send_transfer() {
        // Create a circuit with unchecked send/transfer vulnerability
        let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![],
            vec![create_unchecked_send_transfer_warning()],
            vec![],
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is not satisfied
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }

    #[test]
    fn test_missing_revert() {
        // Create a circuit with missing revert on failure vulnerability
        let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![],
            vec![],
            vec![create_missing_revert_warning()],
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is not satisfied
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }

    #[test]
    fn test_multiple_unchecked_call_vulnerabilities() {
        // Create a circuit with multiple unchecked call vulnerabilities
        let circuit = UncheckedCallsCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![create_unchecked_external_call_warning()],
            vec![create_unchecked_low_level_call_warning()],
            vec![create_unchecked_send_transfer_warning()],
            vec![create_missing_revert_warning()],
        );

        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the constraint system is not satisfied
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 4);
        assert_eq!(cs.num_witness_variables(), 5);
    }
}
