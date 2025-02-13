use ark_ff::fields::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

mod data;
pub use data::*;

/// A circuit that verifies a proof-carrying data chain
#[derive(Clone)]
pub struct PCDCircuit<F: PrimeField> {
    /// Previous state
    pub prev_state: Option<Vec<F>>,
    /// Current state
    pub curr_state: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for PCDCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables for current state as public inputs
        let curr_vars: Vec<FpVar<F>> = self.curr_state
            .iter()
            .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        // If we have a previous state, enforce transition rules
        if let Some(prev_state) = self.prev_state {
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Example transition rule: current state must be previous state plus one
            for (prev, curr) in prev_vars.iter().zip(curr_vars.iter()) {
                let one = FpVar::one();
                let prev_plus_one = prev.clone() + one;
                curr.enforce_equal(&prev_plus_one)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_pcd_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let circuit = PCDCircuit {
            prev_state: Some(vec![Fr::from(1u32)]),
            curr_state: vec![Fr::from(2u32)],
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
