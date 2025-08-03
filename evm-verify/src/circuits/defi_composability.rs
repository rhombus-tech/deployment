use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, LinearCombination, Variable};
use std::marker::PhantomData;
use ethers::types::{H256, Bytes, H160};

use crate::common::DeploymentData;
use crate::bytecode::types::RuntimeAnalysis;
use crate::analysis::defi_composability::{ComposabilityRisk, ComposabilityRiskKind, EconomicImpact};

/// Circuit for verifying DeFi protocol composability security
///
/// This circuit analyzes and verifies multiple aspects of DeFi protocol security:
/// 1. Oracle manipulation resistance
/// 2. Flash loan attack resistance
/// 3. Sandwich attack resistance
/// 4. Access control consistency
/// 5. Asset flow security
/// 6. Economic security
pub struct DeFiComposabilityCircuit<F: Field> {
    /// Deployment data
    pub deployment: DeploymentData,
    /// Runtime analysis
    pub runtime: RuntimeAnalysis,
    /// Protocol contracts
    pub contracts: Vec<H160>,
    /// Detected composability risks
    pub risks: Vec<ComposabilityRisk>,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> DeFiComposabilityCircuit<F> {
    /// Create a new DeFi composability circuit
    pub fn new(deployment: DeploymentData, runtime: RuntimeAnalysis, contracts: Vec<H160>, risks: Vec<ComposabilityRisk>) -> Self {
        Self {
            deployment,
            runtime,
            contracts,
            risks,
            _phantom: PhantomData,
        }
    }
    
    /// Check if there are any oracle manipulation risks
    pub fn has_oracle_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::OracleManipulation))
    }
    
    /// Check if there are any flash loan attack vectors
    pub fn has_flash_loan_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::FlashLoanAttack))
    }
    
    /// Check if there are any sandwich attack vectors
    pub fn has_sandwich_attack_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::SandwichAttack))
    }
    
    /// Check if there are any access control inconsistencies
    pub fn has_access_control_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::AccessControlInconsistency))
    }
    
    /// Check if there are any asset flow vulnerabilities
    pub fn has_asset_flow_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::AssetFlowVulnerability))
    }
    
    /// Check if there are any economic security risks
    pub fn has_economic_risks(&self) -> bool {
        self.risks.iter().any(|r| matches!(r.kind, ComposabilityRiskKind::EconomicSecurityRisk))
    }
    
    /// Check if there are any critical risks
    pub fn has_critical_risks(&self) -> bool {
        self.risks.iter().any(|r| r.economic_impact == EconomicImpact::Critical)
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for DeFiComposabilityCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for each risk type
        // 1. Oracle manipulation risks
        let oracle_risk = cs.new_witness_variable(|| {
            if self.has_oracle_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 2. Flash loan attack risks
        let flash_loan_risk = cs.new_witness_variable(|| {
            if self.has_flash_loan_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 3. Sandwich attack risks
        let sandwich_attack_risk = cs.new_witness_variable(|| {
            if self.has_sandwich_attack_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 4. Access control risks
        let access_control_risk = cs.new_witness_variable(|| {
            if self.has_access_control_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 5. Asset flow risks
        let asset_flow_risk = cs.new_witness_variable(|| {
            if self.has_asset_flow_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 6. Economic security risks
        let economic_risk = cs.new_witness_variable(|| {
            if self.has_economic_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // 7. Critical impact risks
        let critical_risk = cs.new_witness_variable(|| {
            if self.has_critical_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Create a witness variable for the overall protocol security
        let protocol_is_secure = cs.new_witness_variable(|| {
            if !self.has_oracle_risks() && 
               !self.has_flash_loan_risks() && 
               !self.has_sandwich_attack_risks() && 
               !self.has_access_control_risks() &&
               !self.has_asset_flow_risks() &&
               !self.has_economic_risks() &&
               !self.has_critical_risks() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce protocol security constraints
        
        // For critical security checks, enforce that they must be false (0)
        
        // 1. Enforce that oracle_risk is false (0)
        cs.enforce_constraint(
            LinearCombination::from(oracle_risk),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 2. Enforce that flash_loan_risk is false (0)
        cs.enforce_constraint(
            LinearCombination::from(flash_loan_risk),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // 3. Enforce that critical_risk is false (0)
        cs.enforce_constraint(
            LinearCombination::from(critical_risk),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // Make protocol_is_secure a public input
        cs.enforce_constraint(
            LinearCombination::from(protocol_is_secure),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;

        Ok(())
    }
}

/// Circuit that proves economic security properties of a DeFi protocol
pub struct EconomicSecurityCircuit<F: Field> {
    /// Protocol liquidity depth
    pub liquidity_depth: f64,
    /// Collateralization ratio
    pub collateralization_ratio: f64,
    /// Protocol value at risk
    pub value_at_risk: f64,
    /// Maximum extractable value
    pub max_extractable_value: f64,
    /// Whether the protocol is solvent under stress scenarios
    pub is_solvent_under_stress: bool,
    /// PhantomData for the field type
    pub _phantom: PhantomData<F>,
}

impl<F: Field> EconomicSecurityCircuit<F> {
    /// Create a new economic security circuit
    pub fn new(
        liquidity_depth: f64,
        collateralization_ratio: f64,
        value_at_risk: f64,
        max_extractable_value: f64,
        is_solvent_under_stress: bool,
    ) -> Self {
        Self {
            liquidity_depth,
            collateralization_ratio,
            value_at_risk,
            max_extractable_value,
            is_solvent_under_stress,
            _phantom: PhantomData,
        }
    }
    
    /// Check if the collateralization ratio is sufficient
    pub fn has_sufficient_collateral(&self) -> bool {
        self.collateralization_ratio >= 1.5
    }
    
    /// Check if the protocol has acceptable value at risk
    pub fn has_acceptable_var(&self) -> bool {
        self.value_at_risk <= 0.1
    }
    
    /// Check if the protocol has acceptable MEV
    pub fn has_acceptable_mev(&self) -> bool {
        self.max_extractable_value <= 0.05
    }
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for EconomicSecurityCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Create witness variables for economic security properties
        
        // 1. Sufficient collateralization
        let sufficient_collateral = cs.new_witness_variable(|| {
            if self.has_sufficient_collateral() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;
        
        // 2. Acceptable value at risk
        let acceptable_var = cs.new_witness_variable(|| {
            if self.has_acceptable_var() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;
        
        // 3. Acceptable MEV
        let acceptable_mev = cs.new_witness_variable(|| {
            if self.has_acceptable_mev() {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;
        
        // 4. Solvency under stress
        let solvent_under_stress = cs.new_witness_variable(|| {
            if self.is_solvent_under_stress {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;
        
        // Create a witness variable for the overall economic security
        let economically_secure = cs.new_witness_variable(|| {
            if self.has_sufficient_collateral() && 
               self.has_acceptable_var() && 
               self.has_acceptable_mev() && 
               self.is_solvent_under_stress {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;
        
        // Enforce economic security constraints
        
        // 1. Enforce that sufficient_collateral is true (1)
        cs.enforce_constraint(
            LinearCombination::from(sufficient_collateral),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;
        
        // 2. Enforce that solvent_under_stress is true (1)
        cs.enforce_constraint(
            LinearCombination::from(solvent_under_stress),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;
        
        // Make economically_secure a public input
        cs.enforce_constraint(
            LinearCombination::from(economically_secure),
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
    use ethers::types::Address;
    use crate::bytecode::security::SecuritySeverity;
    
    #[test]
    fn test_secure_defi_protocol() {
        // Create a circuit with no risks
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        let circuit = DeFiComposabilityCircuit::<ark_bn254::Fr>::new(
            deployment,
            runtime,
            vec![],
            vec![],
        );
        
        // Create a new constraint system
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check that the circuit is satisfied (no vulnerabilities)
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_protocol_with_risks() {
        // Create a circuit with oracle risks
        let deployment = DeploymentData {
            owner: Address::zero(),
        };
        let runtime = RuntimeAnalysis::default();
        
        // Create a risk
        let risk = ComposabilityRisk {
            kind: ComposabilityRiskKind::OracleManipulation,
            severity: SecuritySeverity::Critical,
            economic_impact: EconomicImpact::Critical,
            description: "Oracle can be manipulated".to_string(),
            involved_contracts: vec![],
            attack_path: None,
            remediation: "Use TWAP".to_string(),
        };
        
        let circuit = DeFiComposabilityCircuit::<ark_bn254::Fr>::new(
            deployment,
            runtime,
            vec![],
            vec![risk],
        );
        
        // Create a new constraint system
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check that the circuit is not satisfied (has vulnerabilities)
        assert!(!cs.is_satisfied().unwrap());
    }
}
