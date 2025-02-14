use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_ec::PairingEngine;
use ark_std::rand::{RngCore, CryptoRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_snark::SNARK;

use crate::circuits::{PCDCircuit, DataPredicateCircuit};

/// Generate proving key for a circuit
pub fn generate_proving_key<E, C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<(ProvingKey<E>, VerifyingKey<E>), anyhow::Error>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: RngCore + CryptoRng,
{
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng)?;
    Ok((pk, vk))
}

/// Generate a proof for a circuit
pub fn generate_proof<E, C, R>(
    circuit: C,
    proving_key: &ProvingKey<E>,
    rng: &mut R,
) -> Result<Vec<u8>, anyhow::Error>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: RngCore + CryptoRng,
{
    let proof = Groth16::<E>::prove(proving_key, circuit, rng)?;
    let mut proof_bytes = Vec::new();
    proof.serialize(&mut proof_bytes)?;
    Ok(proof_bytes)
}

/// Verify a proof
pub fn verify_proof<E>(
    verifying_key: &VerifyingKey<E>,
    proof_bytes: &[u8],
    public_inputs: &[E::Fr],
) -> Result<bool, anyhow::Error>
where
    E: PairingEngine,
{
    let proof = ark_groth16::Proof::deserialize(proof_bytes)?;
    Ok(Groth16::<E>::verify(verifying_key, public_inputs, &proof)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::thread_rng;

    #[test]
    fn test_simple_circuit() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();

        // Create a simple circuit that checks if two values are equal
        let prev_state = vec![Fr::from(1u32)];
        let curr_state = vec![Fr::from(2u32)];
        
        let circuit = PCDCircuit {
            prev_state: Some(prev_state.clone()),
            curr_state: curr_state.clone(),
        };

        // Generate proving and verifying keys
        let (proving_key, verifying_key) = generate_proving_key::<Bls12_381, _, _>(
            circuit.clone(),
            &mut rng,
        )?;

        // Generate proof
        let proof = generate_proof(circuit, &proving_key, &mut rng)?;

        // Collect public inputs
        let mut public_inputs = prev_state;
        public_inputs.extend(curr_state);

        // Verify proof
        assert!(verify_proof(&verifying_key, &proof, &public_inputs)?);

        Ok(())
    }

    #[test]
    fn test_pcd_transition() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();

        // Create a PCD circuit with a state transition
        let prev_state = vec![Fr::from(1u32)];
        let curr_state = vec![Fr::from(2u32)];
        
        let circuit = PCDCircuit {
            prev_state: Some(prev_state.clone()),
            curr_state: curr_state.clone(),
        };

        // Generate proving and verifying keys
        let (proving_key, verifying_key) = generate_proving_key::<Bls12_381, _, _>(
            circuit.clone(),
            &mut rng,
        )?;

        // Generate proof
        let proof = generate_proof(circuit, &proving_key, &mut rng)?;

        // Collect public inputs
        let mut public_inputs = prev_state;
        public_inputs.extend(curr_state);

        // Verify proof
        assert!(verify_proof(&verifying_key, &proof, &public_inputs)?);

        Ok(())
    }

    #[test]
    fn test_data_predicate() -> Result<(), anyhow::Error> {
        let mut rng = thread_rng();

        // Create a data predicate circuit
        let circuit = DataPredicateCircuit {
            input: vec![Fr::from(1u32)],
            output: vec![Fr::from(1u32)],
        };

        // Generate proving and verifying keys
        let (proving_key, verifying_key) = generate_proving_key::<Bls12_381, _, _>(
            circuit.clone(),
            &mut rng,
        )?;

        // Generate proof
        let proof = generate_proof(circuit, &proving_key, &mut rng)?;

        // Verify proof
        assert!(verify_proof(&verifying_key, &proof, &[])?);

        Ok(())
    }
}
