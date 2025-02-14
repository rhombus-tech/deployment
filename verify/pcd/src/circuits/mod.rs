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
        // If we have a previous state, enforce transition rules
        let mut public_inputs = Vec::new();
        
        if let Some(prev_state) = self.prev_state {
            // Add previous state to public inputs first
            let prev_vars: Vec<FpVar<F>> = prev_state
                .iter()
                .enumerate()
                .map(|(_, val)| {
                    let var = FpVar::new_input(cs.clone(), || Ok(*val))?;
                    public_inputs.push(*val);
                    Ok(var)
                })
                .collect::<Result<_, SynthesisError>>()?;

            // Create witness variables for previous state
            let prev_witnesses: Vec<FpVar<F>> = prev_state
                .iter()
                .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Enforce equality between public inputs and witnesses
            for (pub_var, wit_var) in prev_vars.iter().zip(prev_witnesses.iter()) {
                wit_var.enforce_equal(pub_var)?;
            }

            // Create current state variables
            let curr_vars: Vec<FpVar<F>> = self.curr_state
                .iter()
                .enumerate()
                .map(|(_, val)| {
                    let var = FpVar::new_input(cs.clone(), || Ok(*val))?;
                    public_inputs.push(*val);
                    Ok(var)
                })
                .collect::<Result<_, _>>()?;

            // Create witness variables for current state
            let curr_witnesses: Vec<FpVar<F>> = self.curr_state
                .iter()
                .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Enforce equality between public inputs and witnesses
            for (pub_var, wit_var) in curr_vars.iter().zip(curr_witnesses.iter()) {
                wit_var.enforce_equal(pub_var)?;
            }

            // Enforce transition rules
            for (prev, curr) in prev_witnesses.iter().zip(curr_witnesses.iter()) {
                let one = FpVar::constant(F::from(1u32));
                let prev_plus_one = prev.clone() + one;
                curr.enforce_equal(&prev_plus_one)?;
            }
        } else {
            // If no previous state, only handle current state
            let curr_vars: Vec<FpVar<F>> = self.curr_state
                .iter()
                .enumerate()
                .map(|(_, val)| {
                    let var = FpVar::new_input(cs.clone(), || Ok(*val))?;
                    public_inputs.push(*val);
                    Ok(var)
                })
                .collect::<Result<_, _>>()?;

            // Create witness variables for current state
            let curr_witnesses: Vec<FpVar<F>> = self.curr_state
                .iter()
                .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
                .collect::<Result<_, _>>()?;

            // Enforce equality between public inputs and witnesses
            for (pub_var, wit_var) in curr_vars.iter().zip(curr_witnesses.iter()) {
                wit_var.enforce_equal(pub_var)?;
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
