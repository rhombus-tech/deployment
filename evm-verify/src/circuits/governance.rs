use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;

use crate::bytecode::security::SecurityWarning;
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;

/// Circuit for detecting governance vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Insufficient timelock: Governance actions can be executed too quickly
/// 2. Weak quorum requirements: Decisions can be made with too few participants
/// 3. Flash loan voting vulnerability: Voting power can be manipulated with flash loans
/// 4. Centralized admin controls: Excessive power in single admin role
pub struct GovernanceCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Insufficient timelock warnings
    pub insufficient_timelock_warnings: Vec<SecurityWarning>,
    /// Weak quorum requirement warnings
    pub weak_quorum_warnings: Vec<SecurityWarning>,
    /// Flash loan voting vulnerability warnings
    pub flash_loan_voting_warnings: Vec<SecurityWarning>,
    /// Centralized admin control warnings
    pub centralized_admin_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> GovernanceCircuit<F> {
    /// Create a new governance circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            insufficient_timelock_warnings: Vec::new(),
            weak_quorum_warnings: Vec::new(),
            flash_loan_voting_warnings: Vec::new(),
            centralized_admin_warnings: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new governance circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        insufficient_timelock_warnings: Vec<SecurityWarning>,
        weak_quorum_warnings: Vec<SecurityWarning>,
        flash_loan_voting_warnings: Vec<SecurityWarning>,
        centralized_admin_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            insufficient_timelock_warnings,
            weak_quorum_warnings,
            flash_loan_voting_warnings,
            centralized_admin_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any insufficient timelock warnings
    pub fn has_insufficient_timelock(&self) -> bool {
        !self.insufficient_timelock_warnings.is_empty()
    }

    /// Check if there are any weak quorum requirement warnings
    pub fn has_weak_quorum_requirements(&self) -> bool {
        !self.weak_quorum_warnings.is_empty()
    }

    /// Check if there are any flash loan voting vulnerability warnings
    pub fn has_flash_loan_voting_vulnerability(&self) -> bool {
        !self.flash_loan_voting_warnings.is_empty()
    }

    /// Check if there are any centralized admin control warnings
    pub fn has_centralized_admin_controls(&self) -> bool {
        !self.centralized_admin_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for GovernanceCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Insufficient timelock
        let insufficient_timelock = cs.new_witness_variable(|| {
            if self.has_insufficient_timelock() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Weak quorum requirements
        let weak_quorum = cs.new_witness_variable(|| {
            if self.has_weak_quorum_requirements() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Flash loan voting vulnerability
        let flash_loan_voting = cs.new_witness_variable(|| {
            if self.has_flash_loan_voting_vulnerability() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Centralized admin controls
        let centralized_admin = cs.new_witness_variable(|| {
            if self.has_centralized_admin_controls() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 5. Overall contract safety (fifth witness variable)
        let _contract_safety = cs.new_witness_variable(|| {
            if !self.has_insufficient_timelock() && 
               !self.has_weak_quorum_requirements() && 
               !self.has_flash_loan_voting_vulnerability() &&
               !self.has_centralized_admin_controls() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Create constraints for each vulnerability type
        // Each vulnerability witness must be zero (not present) for the circuit to be satisfied

        // 1. Constraint: insufficient_timelock must be zero
        cs.enforce_constraint(
            LinearCombination::from(insufficient_timelock),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 2. Constraint: weak_quorum must be zero
        cs.enforce_constraint(
            LinearCombination::from(weak_quorum),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 3. Constraint: flash_loan_voting must be zero
        cs.enforce_constraint(
            LinearCombination::from(flash_loan_voting),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 4. Constraint: centralized_admin must be zero
        cs.enforce_constraint(
            LinearCombination::from(centralized_admin),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // The circuit is satisfied if all vulnerability witnesses are zero
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::H160 as Address;
    use ark_bn254::Fr;

    // Helper function to create a mock deployment
    fn create_mock_deployment() -> DeploymentData {
        DeploymentData {
            owner: Address::zero(),
        }
    }

    // Helper function to create a mock runtime analysis
    fn create_mock_runtime() -> RuntimeAnalysis {
        RuntimeAnalysis::default()
    }

    #[test]
    fn test_safe_governance_contract() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let circuit = GovernanceCircuit::<Fr>::new(deployment, runtime);
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should be satisfied since there are no vulnerabilities
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_insufficient_timelock() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let warning = SecurityWarning::insufficient_timelock(0);
        
        let circuit = GovernanceCircuit::<Fr>::with_warnings(
            deployment,
            runtime,
            vec![warning],
            vec![],
            vec![],
            vec![],
        );
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should not be satisfied due to insufficient timelock
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_weak_quorum_requirements() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let warning = SecurityWarning::weak_quorum_requirement(0);
        
        let circuit = GovernanceCircuit::<Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![warning],
            vec![],
            vec![],
        );
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should not be satisfied due to weak quorum requirements
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_flash_loan_voting_vulnerability() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let warning = SecurityWarning::flash_loan_voting_vulnerability(0);
        
        let circuit = GovernanceCircuit::<Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![],
            vec![warning],
            vec![],
        );
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should not be satisfied due to flash loan voting vulnerability
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_centralized_admin_controls() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let warning = SecurityWarning::centralized_admin_control(0);
        
        let circuit = GovernanceCircuit::<Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![],
            vec![],
            vec![warning],
        );
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should not be satisfied due to centralized admin controls
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_multiple_governance_vulnerabilities() {
        let deployment = create_mock_deployment();
        let runtime = create_mock_runtime();
        
        let timelock_warning = SecurityWarning::insufficient_timelock(0);
        let quorum_warning = SecurityWarning::weak_quorum_requirement(0);
        
        let circuit = GovernanceCircuit::<Fr>::with_warnings(
            deployment,
            runtime,
            vec![timelock_warning],
            vec![quorum_warning],
            vec![],
            vec![],
        );
        
        // Create a constraint system
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // The circuit should not be satisfied due to multiple vulnerabilities
        assert!(!cs.is_satisfied().unwrap());
    }
}
