use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use crate::analyzer::bytecode::VulnerabilityType;
use ethers::types::U256;

/// Circuit for verifying bytecode safety properties
#[derive(Clone)]
pub struct BytecodeSafetyCircuit<F: Field> {
    // Vulnerability indicators (1 if present, 0 if not)
    reentrancy_present: bool,
    integer_overflow_present: bool,
    unbounded_loop_present: bool,
    unchecked_call_present: bool,
    access_control_present: bool,
    
    // Gas usage and complexity metrics
    gas_usage: U256,
    complexity: u32,
    
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> BytecodeSafetyCircuit<F> {
    pub fn new(
        vulnerabilities: &[VulnerabilityType],
        gas_usage: U256,
        complexity: u32
    ) -> Self {
        println!("Creating bytecode safety circuit with {} vulnerabilities", vulnerabilities.len());
        
        // Check for each vulnerability type
        let reentrancy_present = vulnerabilities.contains(&VulnerabilityType::Reentrancy);
        let integer_overflow_present = vulnerabilities.contains(&VulnerabilityType::IntegerOverflow);
        let unbounded_loop_present = vulnerabilities.contains(&VulnerabilityType::UnboundedLoop);
        let unchecked_call_present = vulnerabilities.contains(&VulnerabilityType::UncheckedCall);
        let access_control_present = vulnerabilities.contains(&VulnerabilityType::AccessControl);
        
        println!("Vulnerability indicators:");
        println!("  Reentrancy: {}", reentrancy_present);
        println!("  Integer Overflow: {}", integer_overflow_present);
        println!("  Unbounded Loop: {}", unbounded_loop_present);
        println!("  Unchecked Call: {}", unchecked_call_present);
        println!("  Access Control: {}", access_control_present);
        
        Self {
            reentrancy_present,
            integer_overflow_present,
            unbounded_loop_present,
            unchecked_call_present,
            access_control_present,
            gas_usage,
            complexity,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for BytecodeSafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        println!("Generating bytecode safety constraints...");
        
        // Create witnesses for each vulnerability indicator
        let reentrancy = cs.new_witness_variable(|| Ok(F::from(self.reentrancy_present as u32)))?;
        let integer_overflow = cs.new_witness_variable(|| Ok(F::from(self.integer_overflow_present as u32)))?;
        let unbounded_loop = cs.new_witness_variable(|| Ok(F::from(self.unbounded_loop_present as u32)))?;
        let unchecked_call = cs.new_witness_variable(|| Ok(F::from(self.unchecked_call_present as u32)))?;
        let access_control = cs.new_witness_variable(|| Ok(F::from(self.access_control_present as u32)))?;
        
        // Create a public input for whether the bytecode is safe
        let is_safe = cs.new_input_variable(|| {
            let safe = !self.reentrancy_present && 
                      !self.integer_overflow_present && 
                      !self.unbounded_loop_present && 
                      !self.unchecked_call_present && 
                      !self.access_control_present;
            println!("is_safe = {}", safe as u32);
            Ok(F::from(safe as u32))
        })?;
        
        // Enforce that each vulnerability indicator is boolean (0 or 1)
        for &var in &[reentrancy, integer_overflow, unbounded_loop, unchecked_call, access_control] {
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), var)]);
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), var)]);
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::one(), var)]);
            cs.enforce_constraint(lc1, lc2, lc3)?;
        }
        
        // Enforce that is_safe is 1 if and only if all vulnerability indicators are 0
        
        // First, compute the OR of all vulnerability indicators
        // We'll use a simple approach: any_vulnerability = reentrancy + integer_overflow + ...
        // If any vulnerability is present, any_vulnerability will be > 0
        let any_vulnerability = cs.new_witness_variable(|| {
            let sum = (self.reentrancy_present as u32) + 
                     (self.integer_overflow_present as u32) + 
                     (self.unbounded_loop_present as u32) + 
                     (self.unchecked_call_present as u32) + 
                     (self.access_control_present as u32);
            let any = sum > 0;
            println!("any_vulnerability = {}", any as u32);
            Ok(F::from(any as u32))
        })?;
        
        // Enforce that any_vulnerability is boolean
        let mut lc1 = LinearCombination::new();
        lc1.extend(vec![(F::one(), any_vulnerability)]);
        let mut lc2 = LinearCombination::new();
        lc2.extend(vec![(F::one(), any_vulnerability)]);
        let mut lc3 = LinearCombination::new();
        lc3.extend(vec![(F::one(), any_vulnerability)]);
        cs.enforce_constraint(lc1, lc2, lc3)?;
        
        // Enforce that is_safe = 1 - any_vulnerability
        let mut lc1 = LinearCombination::new();
        lc1.extend(vec![(F::one(), Variable::One), (-F::one(), any_vulnerability)]);
        let mut lc2 = LinearCombination::new();
        lc2.extend(vec![(F::one(), Variable::One)]);
        let mut lc3 = LinearCombination::new();
        lc3.extend(vec![(F::one(), is_safe)]);
        cs.enforce_constraint(lc1, lc2, lc3)?;
        
        // Create witnesses for gas usage and complexity
        // Note: For simplicity, we're just using u64 values here
        let _gas_usage_witness = cs.new_witness_variable(|| Ok(F::from(self.gas_usage.as_u64())))?;
        let _complexity_witness = cs.new_witness_variable(|| Ok(F::from(self.complexity as u64)))?;
        
        // We could add constraints on gas usage and complexity if needed
        // For example, we could enforce that gas_usage <= some_max_value
        
        println!("Generated {} constraints", cs.num_constraints());
        Ok(())
    }
}
