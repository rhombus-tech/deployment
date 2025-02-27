use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

/// A circuit that verifies data predicates
#[derive(Clone)]
pub struct DataPredicateCircuit<F: PrimeField> {
    /// Input data
    pub input: Vec<F>,
    /// Output data
    pub output: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DataPredicateCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Create variables for input and output as public inputs
        let input_vars: Vec<FpVar<F>> = self.input
            .iter()
            .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        let output_vars: Vec<FpVar<F>> = self.output
            .iter()
            .map(|val| FpVar::new_input(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;

        // Example predicate: output must equal input
        for (input, output) in input_vars.iter().zip(output_vars.iter()) {
            output.enforce_equal(input)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_data_predicate() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let circuit = DataPredicateCircuit {
            input: vec![Fr::from(1u32)],
            output: vec![Fr::from(1u32)],
        };

        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }
}
