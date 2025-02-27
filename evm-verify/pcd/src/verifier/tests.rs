use ark_bn254::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use crate::{
    prover::{tests::TestMultiplyCircuit, PCDProver},
};

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

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
