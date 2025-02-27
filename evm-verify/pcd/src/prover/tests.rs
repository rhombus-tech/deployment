use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;

use crate::circuits::PCDCircuit;
use crate::verifier::PCDVerifier;

use super::*;

#[derive(Clone)]
pub struct TestMultiplyCircuit {
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
}

impl PCDCircuit for TestMultiplyCircuit {
    fn get_public_inputs(&self) -> Vec<Fr> {
        vec![self.a, self.b, self.c]
    }
    
    fn get_public_outputs(&self) -> Vec<Fr> {
        vec![self.c]
    }
    
    fn verify_chain(&self, prev_outputs: &[Fr]) -> Result<bool, SynthesisError> {
        if prev_outputs.is_empty() {
            return Ok(true);
        }
        Ok(self.a == prev_outputs[0])
    }
}

impl ConstraintSynthesizer<Fr> for TestMultiplyCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let a = cs.new_witness_variable(|| Ok(self.a))?;
        let b = cs.new_witness_variable(|| Ok(self.b))?;
        let c = cs.new_input_variable(|| Ok(self.c))?;
        
        cs.enforce_constraint(
            ark_relations::lc!() + a,
            ark_relations::lc!() + b,
            ark_relations::lc!() + c,
        )?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_verify() -> Result<(), anyhow::Error> {
        let mut rng = StdRng::from_entropy();
        
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let circuit = TestMultiplyCircuit { a, b, c };
        
        let prover = PCDProver::new(&circuit)?;
        let proof = prover.prove(&circuit)?;
        
        assert!(prover.verify(&proof, &[a, b, c])?);
        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<(), anyhow::Error> {
        let mut rng = StdRng::from_entropy();
        
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let circuit = TestMultiplyCircuit { a, b, c };
        
        let prover = PCDProver::new(&circuit)?;
        let proof = prover.prove(&circuit)?;
        
        // Try to verify with wrong inputs
        let wrong_a = Fr::rand(&mut rng);
        assert!(!prover.verify(&proof, &[wrong_a, b, c])?);
        Ok(())
    }

    #[test]
    fn test_verify_chain() -> Result<(), anyhow::Error> {
        let mut rng = StdRng::from_entropy();
        
        // Create first circuit: a * b = c
        let a1 = Fr::rand(&mut rng);
        let b1 = Fr::rand(&mut rng);
        let c1 = a1 * b1;
        let circuit1 = TestMultiplyCircuit { a: a1, b: b1, c: c1 };
        
        // Create second circuit: c * d = e
        let b2 = Fr::rand(&mut rng);
        let c2 = c1 * b2;
        let circuit2 = TestMultiplyCircuit { a: c1, b: b2, c: c2 };

        // Create provers and generate proofs
        let prover1 = PCDProver::new(&circuit1)?;
        let prover2 = PCDProver::new(&circuit2)?;
        
        let proof1 = prover1.prove(&circuit1)?;
        let proof2 = prover2.prove(&circuit2)?;
        
        // Create verifier and verify chain
        let verifier = PCDVerifier::new(vec![
            prover1.verification_key().clone(),
            prover2.verification_key().clone(),
        ]);
        
        assert!(verifier.verify_chain(&[&circuit1, &circuit2], &[proof1, proof2])?);
        Ok(())
    }

    #[test]
    fn test_invalid_chain() -> Result<(), anyhow::Error> {
        let mut rng = StdRng::from_entropy();
        
        // Create first circuit: a * b = c
        let a1 = Fr::rand(&mut rng);
        let b1 = Fr::rand(&mut rng);
        let c1 = a1 * b1;
        let circuit1 = TestMultiplyCircuit { a: a1, b: b1, c: c1 };
        
        // Create second circuit with invalid input (should be c1)
        let a2 = Fr::rand(&mut rng); // Different from c1
        let b2 = Fr::rand(&mut rng);
        let c2 = a2 * b2;
        let circuit2 = TestMultiplyCircuit { a: a2, b: b2, c: c2 };

        // Create provers and generate proofs
        let prover1 = PCDProver::new(&circuit1)?;
        let prover2 = PCDProver::new(&circuit2)?;
        
        let proof1 = prover1.prove(&circuit1)?;
        let proof2 = prover2.prove(&circuit2)?;
        
        // Create verifier and verify chain
        let verifier = PCDVerifier::new(vec![
            prover1.verification_key().clone(),
            prover2.verification_key().clone(),
        ]);
        
        // Should fail because a2 != c1
        assert!(!verifier.verify_chain(&[&circuit1, &circuit2], &[proof1, proof2])?);
        Ok(())
    }
}
