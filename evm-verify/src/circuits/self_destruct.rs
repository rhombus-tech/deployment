use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;

/// Circuit for detecting self-destruct vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Unprotected self-destruct: Self-destruct operations without proper access control
/// 2. Delegatecall to contracts with self-destruct: Indirect self-destruct via delegatecall
/// 3. Self-destruct in constructor: Self-destruct operations in contract constructor
/// 4. Conditional self-destruct: Self-destruct operations with weak conditions
pub struct SelfDestructCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Unprotected self-destruct warnings
    pub unprotected_self_destruct_warnings: Vec<SecurityWarning>,
    /// Delegatecall to self-destruct warnings
    pub delegatecall_self_destruct_warnings: Vec<SecurityWarning>,
    /// Self-destruct in constructor warnings
    pub self_destruct_in_constructor_warnings: Vec<SecurityWarning>,
    /// Conditional self-destruct warnings
    pub conditional_self_destruct_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> SelfDestructCircuit<F> {
    /// Create a new self-destruct circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            unprotected_self_destruct_warnings: Vec::new(),
            delegatecall_self_destruct_warnings: Vec::new(),
            self_destruct_in_constructor_warnings: Vec::new(),
            conditional_self_destruct_warnings: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new self-destruct circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        unprotected_self_destruct_warnings: Vec<SecurityWarning>,
        delegatecall_self_destruct_warnings: Vec<SecurityWarning>,
        self_destruct_in_constructor_warnings: Vec<SecurityWarning>,
        conditional_self_destruct_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            unprotected_self_destruct_warnings,
            delegatecall_self_destruct_warnings,
            self_destruct_in_constructor_warnings,
            conditional_self_destruct_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any unprotected self-destruct warnings
    pub fn has_unprotected_self_destruct(&self) -> bool {
        !self.unprotected_self_destruct_warnings.is_empty()
    }

    /// Check if there are any delegatecall to self-destruct warnings
    pub fn has_delegatecall_self_destruct(&self) -> bool {
        !self.delegatecall_self_destruct_warnings.is_empty()
    }

    /// Check if there are any self-destruct in constructor warnings
    pub fn has_self_destruct_in_constructor(&self) -> bool {
        !self.self_destruct_in_constructor_warnings.is_empty()
    }

    /// Check if there are any conditional self-destruct warnings
    pub fn has_conditional_self_destruct(&self) -> bool {
        !self.conditional_self_destruct_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for SelfDestructCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Unprotected self-destruct
        let unprotected_self_destruct = cs.new_witness_variable(|| {
            if self.has_unprotected_self_destruct() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Delegatecall to self-destruct
        let delegatecall_self_destruct = cs.new_witness_variable(|| {
            if self.has_delegatecall_self_destruct() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Self-destruct in constructor
        let self_destruct_in_constructor = cs.new_witness_variable(|| {
            if self.has_self_destruct_in_constructor() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Conditional self-destruct
        let conditional_self_destruct = cs.new_witness_variable(|| {
            if self.has_conditional_self_destruct() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 5. Overall contract safety status
        let contract_vulnerable = cs.new_witness_variable(|| {
            if self.has_unprotected_self_destruct() 
                || self.has_delegatecall_self_destruct()
                || self.has_self_destruct_in_constructor()
                || self.has_conditional_self_destruct() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce constraints for each vulnerability type
        // 1. Enforce unprotected_self_destruct == 0
        cs.enforce_constraint(
            LinearCombination::from(unprotected_self_destruct),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 2. Enforce delegatecall_self_destruct == 0
        cs.enforce_constraint(
            LinearCombination::from(delegatecall_self_destruct),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 3. Enforce self_destruct_in_constructor == 0
        cs.enforce_constraint(
            LinearCombination::from(self_destruct_in_constructor),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::Zero),
        )?;

        // 4. Enforce conditional_self_destruct == 0
        cs.enforce_constraint(
            LinearCombination::from(conditional_self_destruct),
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

    // Helper function to create an unprotected self-destruct warning
    fn create_unprotected_self_destruct_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UnprotectedSelfDestruct,
            SecuritySeverity::Critical,
            0,
            "Unprotected self-destruct detected".to_string(),
            vec![Operation::SelfDestruct {
                beneficiary: H256::zero(),
            }],
            "Add proper access control to self-destruct operations".to_string(),
        )
    }

    // Helper function to create a delegatecall to self-destruct warning
    fn create_delegatecall_self_destruct_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::DelegateCallMisuse,
            SecuritySeverity::Critical,
            0,
            "Delegatecall to contract with self-destruct detected".to_string(),
            vec![Operation::DelegateCall {
                target: H256::zero(),
                data: vec![],
            }],
            "Verify delegatecall targets do not contain self-destruct operations".to_string(),
        )
    }

    // Helper function to create a self-destruct in constructor warning
    fn create_self_destruct_in_constructor_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UnprotectedSelfDestruct,
            SecuritySeverity::Critical,
            0,
            "Self-destruct in constructor detected".to_string(),
            vec![Operation::SelfDestruct {
                beneficiary: H256::zero(),
            }],
            "Remove self-destruct from constructor".to_string(),
        )
    }

    // Helper function to create a conditional self-destruct warning
    fn create_conditional_self_destruct_warning() -> SecurityWarning {
        SecurityWarning::new(
            SecurityWarningKind::UnprotectedSelfDestruct,
            SecuritySeverity::High,
            0,
            "Conditional self-destruct with weak conditions detected".to_string(),
            vec![
                Operation::Comparison {
                    op_type: "weak_condition".to_string(),
                },
                Operation::SelfDestruct {
                    beneficiary: H256::zero(),
                },
            ],
            "Strengthen conditions for self-destruct operations".to_string(),
        )
    }

    #[test]
    fn test_safe_contract() {
        // Create a circuit with no vulnerabilities
        let circuit = SelfDestructCircuit::<Fr>::new(
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
    fn test_unprotected_self_destruct() {
        // Create a circuit with unprotected self-destruct vulnerability
        let circuit = SelfDestructCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![create_unprotected_self_destruct_warning()],
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
    fn test_delegatecall_self_destruct() {
        // Create a circuit with delegatecall to self-destruct vulnerability
        let circuit = SelfDestructCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![create_delegatecall_self_destruct_warning()],
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
    fn test_self_destruct_in_constructor() {
        // Create a circuit with self-destruct in constructor vulnerability
        let circuit = SelfDestructCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![],
            vec![create_self_destruct_in_constructor_warning()],
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
    fn test_conditional_self_destruct() {
        // Create a circuit with conditional self-destruct vulnerability
        let circuit = SelfDestructCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![],
            vec![],
            vec![],
            vec![create_conditional_self_destruct_warning()],
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
    fn test_multiple_self_destruct_vulnerabilities() {
        // Create a circuit with multiple self-destruct vulnerabilities
        let circuit = SelfDestructCircuit::<Fr>::with_warnings(
            create_mock_deployment(),
            create_mock_runtime(),
            vec![create_unprotected_self_destruct_warning()],
            vec![create_delegatecall_self_destruct_warning()],
            vec![create_self_destruct_in_constructor_warning()],
            vec![create_conditional_self_destruct_warning()],
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
