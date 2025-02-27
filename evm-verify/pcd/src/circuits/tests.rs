use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::*,
};

use super::PCDCircuit;

#[derive(Clone)]
pub struct TestAddCircuit {
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
}

impl PCDCircuit for TestAddCircuit {
    fn get_public_inputs(&self) -> Vec<Fr> {
        vec![self.a, self.b]
    }

    fn get_public_outputs(&self) -> Vec<Fr> {
        vec![self.c]
    }

    fn verify_chain(&self, prev_outputs: &[Fr]) -> Result<bool, SynthesisError> {
        Ok(prev_outputs.is_empty() || prev_outputs[0] == self.a)
    }
}

impl ConstraintSynthesizer<Fr> for TestAddCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let c = FpVar::new_witness(cs.clone(), || Ok(self.c))?;

        let sum = &a + &b;
        sum.enforce_equal(&c)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_constraint_generation() -> Result<(), SynthesisError> {
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a + b;

        let circuit = TestAddCircuit { a, b, c };
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone())?;
        
        assert!(cs.is_satisfied()?);
        Ok(())
    }
}
