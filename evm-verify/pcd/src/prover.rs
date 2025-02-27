use ark_bn254::{Bn254, Fr};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_std::rand::{RngCore, CryptoRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use ark_snark::SNARK;

use crate::circuits::{PCDCircuit, DataPredicateCircuit};

/// Generate proving key for a circuit
pub fn generate_proving_key<C, R>(
    circuit: C,
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), anyhow::Error>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)?;
    Ok((pk, vk))
}

/// Generate a proof for a circuit
pub fn generate_proof<C, R>(
    circuit: C,
    proving_key: &ProvingKey<Bn254>,
    rng: &mut R,
) -> Result<Vec<u8>, anyhow::Error>
where
    C: ConstraintSynthesizer<Fr>,
    R: RngCore + CryptoRng,
{
    let proof = Groth16::<Bn254>::prove(proving_key, circuit, rng)?;
    let mut proof_bytes = Vec::new();
    proof.serialize_with_mode(&mut proof_bytes, Compress::Yes)?;
    Ok(proof_bytes)
}

/// Verify a proof
pub fn verify_proof(
    verifying_key: &VerifyingKey<Bn254>,
    proof_bytes: &[u8],
    public_inputs: &[Fr],
) -> Result<bool, anyhow::Error>
{
    let proof = Proof::deserialize_with_mode(proof_bytes, Compress::Yes, Validate::Yes)?;
    Ok(Groth16::<Bn254>::verify(verifying_key, public_inputs, &proof)?)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let (proving_key, verifying_key) = generate_proving_key(
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
        let input = vec![Fr::from(1u32)];
        let output = vec![Fr::from(1u32)];
        
        let circuit = DataPredicateCircuit {
            input: input.clone(),
            output: output.clone(),
        };

        // Generate proving and verifying keys
        let (proving_key, verifying_key) = generate_proving_key(
            circuit.clone(),
            &mut rng,
        )?;

        // Generate proof
        let proof = generate_proof(circuit, &proving_key, &mut rng)?;

        // Collect public inputs
        let mut public_inputs = input;
        public_inputs.extend(output);

        // Verify proof
        assert!(verify_proof(&verifying_key, &proof, &public_inputs)?);

        Ok(())
    }
}
