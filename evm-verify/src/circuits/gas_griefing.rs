use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;

use crate::bytecode::security::SecurityWarning;
use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;

/// Circuit for detecting gas griefing vulnerabilities
///
/// This circuit checks for the following vulnerabilities:
/// 1. Forward gas griefing: Not forwarding enough gas to a called contract
/// 2. Gas exhaustion: Consuming all available gas before critical operations
/// 3. Gas price manipulation: Exploiting gas price dependencies
/// 4. Callback gas griefing: Not providing enough gas for callbacks
pub struct GasGriefingCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Forward gas griefing warnings
    pub forward_gas_griefing_warnings: Vec<SecurityWarning>,
    /// Gas exhaustion warnings
    pub gas_exhaustion_warnings: Vec<SecurityWarning>,
    /// Gas price manipulation warnings
    pub gas_price_manipulation_warnings: Vec<SecurityWarning>,
    /// Callback gas griefing warnings
    pub callback_gas_griefing_warnings: Vec<SecurityWarning>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> GasGriefingCircuit<F> {
    /// Create a new gas griefing circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis) -> Self {
        Self {
            deployment,
            runtime,
            forward_gas_griefing_warnings: Vec::new(),
            gas_exhaustion_warnings: Vec::new(),
            gas_price_manipulation_warnings: Vec::new(),
            callback_gas_griefing_warnings: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new gas griefing circuit with specific warnings
    pub fn with_warnings(
        deployment: DeploymentData,
        runtime: RuntimeAnalysis,
        forward_gas_griefing_warnings: Vec<SecurityWarning>,
        gas_exhaustion_warnings: Vec<SecurityWarning>,
        gas_price_manipulation_warnings: Vec<SecurityWarning>,
        callback_gas_griefing_warnings: Vec<SecurityWarning>,
    ) -> Self {
        Self {
            deployment,
            runtime,
            forward_gas_griefing_warnings,
            gas_exhaustion_warnings,
            gas_price_manipulation_warnings,
            callback_gas_griefing_warnings,
            _phantom: PhantomData,
        }
    }

    /// Check if there are any forward gas griefing warnings
    pub fn has_forward_gas_griefing(&self) -> bool {
        !self.forward_gas_griefing_warnings.is_empty()
    }

    /// Check if there are any gas exhaustion warnings
    pub fn has_gas_exhaustion(&self) -> bool {
        !self.gas_exhaustion_warnings.is_empty()
    }

    /// Check if there are any gas price manipulation warnings
    pub fn has_gas_price_manipulation(&self) -> bool {
        !self.gas_price_manipulation_warnings.is_empty()
    }

    /// Check if there are any callback gas griefing warnings
    pub fn has_callback_gas_griefing(&self) -> bool {
        !self.callback_gas_griefing_warnings.is_empty()
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for GasGriefingCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each vulnerability type
        // 1. Forward gas griefing
        let forward_gas_griefing = cs.new_witness_variable(|| {
            if self.has_forward_gas_griefing() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Gas exhaustion
        let gas_exhaustion = cs.new_witness_variable(|| {
            if self.has_gas_exhaustion() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Gas price manipulation
        let gas_price_manipulation = cs.new_witness_variable(|| {
            if self.has_gas_price_manipulation() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Callback gas griefing
        let callback_gas_griefing = cs.new_witness_variable(|| {
            if self.has_callback_gas_griefing() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Create a witness variable for the overall contract safety
        let contract_is_safe = cs.new_witness_variable(|| {
            if !self.has_forward_gas_griefing() && 
               !self.has_gas_exhaustion() && 
               !self.has_gas_price_manipulation() && 
               !self.has_callback_gas_griefing() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce that the contract is safe
        // This is equivalent to enforcing that each vulnerability is not present
        
        // 1. Enforce that forward_gas_griefing is false (0)
        cs.enforce_constraint(
            LinearCombination::from(forward_gas_griefing),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 2. Enforce that gas_exhaustion is false (0)
        cs.enforce_constraint(
            LinearCombination::from(gas_exhaustion),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 3. Enforce that gas_price_manipulation is false (0)
        cs.enforce_constraint(
            LinearCombination::from(gas_price_manipulation),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 4. Enforce that callback_gas_griefing is false (0)
        cs.enforce_constraint(
            LinearCombination::from(callback_gas_griefing),
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

    #[test]
    fn test_safe_contract() {
        // Create a circuit with no vulnerabilities
        let deployment = DeploymentData {
            owner: ethers::types::H160::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = GasGriefingCircuit::<ark_bn254::Fr>::new(deployment, runtime);

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
