use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

mod prover;
pub mod circuits;

pub use prover::{
    generate_proving_key,
    generate_proof,
    verify_proof,
};

/// Our specific PCD predicate implementation
#[derive(Clone)]
pub struct RhombusPredicate<F: PrimeField> {
    /// Previous state in the computation
    pub prev_state: Option<Vec<F>>,
    /// Current state
    pub curr_state: Vec<F>,
    /// Local computation data
    pub local_data: Option<Vec<F>>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RhombusPredicate<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // 1. Allocate current state variables
        let curr_vars: Vec<FpVar<F>> = self.curr_state
            .iter()
            .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        // 2. If we have a previous state, verify the transition
        if let Some(prev_state) = self.prev_state {
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Example transition rule: current state must be >= previous state
            for (prev, curr) in prev_vars.iter().zip(curr_vars.iter()) {
                // In a prime field this is always true, but serves as an example
                let one = FpVar::one();
                let prev_plus_one = prev.clone() + one;
                curr.enforce_equal(&prev_plus_one)?;
            }
        }

        // 3. If we have local data, verify the computation
        if let Some(local_data) = self.local_data {
            let local_vars: Vec<FpVar<F>> = local_data
                .iter()
                .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Example: local computation results must match current state
            for (local, curr) in local_vars.iter().zip(curr_vars.iter()) {
                curr.enforce_equal(local)?;
            }
        }

        Ok(())
    }
}

/// A simple circuit that checks if two values are equal
#[derive(Clone)]
pub struct SimpleCircuit<F: PrimeField> {
    /// First value
    pub a: F,
    /// Second value
    pub b: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for SimpleCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables
        let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?;

        // Enforce that a equals b
        a.enforce_equal(&b)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_base_case() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let predicate = RhombusPredicate {
            prev_state: None,
            curr_state: vec![Fr::from(1u32)],
            local_data: None,
        };

        assert!(predicate.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_transition() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let predicate = RhombusPredicate {
            prev_state: Some(vec![Fr::from(1u32)]),
            curr_state: vec![Fr::from(2u32)],
            local_data: Some(vec![Fr::from(2u32)]),
        };

        assert!(predicate.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_simple_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let circuit = SimpleCircuit {
            a: Fr::from(1u32),
            b: Fr::from(1u32),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());

        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let circuit = SimpleCircuit {
            a: Fr::from(1u32),
            b: Fr::from(2u32),
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }
}
