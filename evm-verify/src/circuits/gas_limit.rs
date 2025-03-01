use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;

use crate::bytecode::security::SecurityWarning;
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;

/// Circuit for detecting gas limit vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Block gas limit dependency: Contract logic depends on block.gaslimit
/// 2. Gas-intensive loops: Loops that might consume excessive gas
/// 3. Unbounded operations: Operations that might exceed block gas limit
pub struct GasLimitCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Block gas limit dependency warnings
    pub gas_limit_dependency_warnings: Vec<SecurityWarning>,
    /// Gas-intensive loop warnings
    pub gas_intensive_loop_warnings: Vec<SecurityWarning>,
    /// Unbounded operation warnings
    pub unbounded_operation_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> GasLimitCircuit<F> {
    /// Create a new gas limit circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            gas_limit_dependency_warnings: Vec::new(),
            gas_intensive_loop_warnings: Vec::new(),
            unbounded_operation_warnings: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new gas limit circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        gas_limit_dependency_warnings: Vec<SecurityWarning>,
        gas_intensive_loop_warnings: Vec<SecurityWarning>,
        unbounded_operation_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            gas_limit_dependency_warnings,
            gas_intensive_loop_warnings,
            unbounded_operation_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any block gas limit dependency warnings
    pub fn has_gas_limit_dependency(&self) -> bool {
        !self.gas_limit_dependency_warnings.is_empty()
    }

    /// Check if there are any gas-intensive loop warnings
    pub fn has_gas_intensive_loops(&self) -> bool {
        !self.gas_intensive_loop_warnings.is_empty()
    }

    /// Check if there are any unbounded operation warnings
    pub fn has_unbounded_operations(&self) -> bool {
        !self.unbounded_operation_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for GasLimitCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Block gas limit dependency
        let gas_limit_dependency = cs.new_witness_variable(|| {
            if self.has_gas_limit_dependency() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Gas-intensive loops
        let gas_intensive_loops = cs.new_witness_variable(|| {
            if self.has_gas_intensive_loops() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Unbounded operations
        let unbounded_operations = cs.new_witness_variable(|| {
            if self.has_unbounded_operations() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Overall contract safety (fourth witness variable)
        let _contract_safety = cs.new_witness_variable(|| {
            if !self.has_gas_limit_dependency() && 
               !self.has_gas_intensive_loops() && 
               !self.has_unbounded_operations() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Create constraints for each vulnerability type
        // Each vulnerability witness must be zero (not present) for the circuit to be satisfied

        // 1. Constraint: gas_limit_dependency must be zero
        cs.enforce_constraint(
            LinearCombination::from(gas_limit_dependency),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 2. Constraint: gas_intensive_loops must be zero
        cs.enforce_constraint(
            LinearCombination::from(gas_intensive_loops),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 3. Constraint: unbounded_operations must be zero
        cs.enforce_constraint(
            LinearCombination::from(unbounded_operations),
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
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_safe_contract() {
        // Create a circuit with no vulnerabilities
        let deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = GasLimitCircuit::<ark_bn254::Fr>::new(deployment, runtime);

        // Check that the circuit is satisfied
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 3);
    }

    #[test]
    fn test_gas_limit_dependency() {
        // Create a warning for gas limit dependency
        let warning = SecurityWarning::new(
            crate::bytecode::security::SecurityWarningKind::Other("BlockGasLimitDependence".to_string()),
            crate::bytecode::security::SecuritySeverity::Medium,
            0,
            "Block gas limit dependence detected".to_string(),
            vec![],
            "Avoid relying on block gas limit for critical contract logic".to_string(),
        );

        // Create a circuit with gas limit dependency
        let deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![warning],
            vec![],
            vec![],
        );

        // Check that the circuit is not satisfied
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 3);
    }

    #[test]
    fn test_gas_intensive_loops() {
        // Create a warning for gas-intensive loops
        let warning = SecurityWarning::new(
            crate::bytecode::security::SecurityWarningKind::Other("GasIntensiveLoop".to_string()),
            crate::bytecode::security::SecuritySeverity::Medium,
            0,
            "Gas-intensive loop detected".to_string(),
            vec![],
            "Consider implementing gas optimizations for loops".to_string(),
        );

        // Create a circuit with gas-intensive loops
        let deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![warning],
            vec![],
        );

        // Check that the circuit is not satisfied
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 3);
    }

    #[test]
    fn test_unbounded_operations() {
        // Create a warning for unbounded operations
        let warning = SecurityWarning::new(
            crate::bytecode::security::SecurityWarningKind::Other("UnboundedOperation".to_string()),
            crate::bytecode::security::SecuritySeverity::High,
            0,
            "Unbounded operation detected".to_string(),
            vec![],
            "Implement bounds for operations to prevent gas limit issues".to_string(),
        );

        // Create a circuit with unbounded operations
        let deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = GasLimitCircuit::<ark_bn254::Fr>::with_warnings(
            deployment,
            runtime,
            vec![],
            vec![],
            vec![warning],
        );

        // Check that the circuit is not satisfied
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 3);
    }
}
