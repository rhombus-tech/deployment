use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Field;
use ark_groth16::{
    Groth16,
    prepare_verifying_key,
    Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use anyhow::Result;

/// Generate proving and verifying keys for a circuit
pub fn generate_proving_key<C>(
    circuit: &C,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)>
where
    C: ConstraintSynthesizer<Fr> + Clone,
{
    let seed: [u8; 32] = [42; 32]; // Fixed seed for deterministic testing
    let mut rng = StdRng::from_seed(seed);
    let (params, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut rng)?;
    Ok((params, vk))
}

/// Generate a proof for a circuit
pub fn generate_proof<C>(
    circuit: C,
    proving_key: &ProvingKey<Bls12_381>,
) -> Result<Proof<Bls12_381>>
where
    C: ConstraintSynthesizer<Fr>,
{
    let seed: [u8; 32] = [42; 32]; // Fixed seed for deterministic testing
    let mut rng = StdRng::from_seed(seed);
    let proof = Groth16::<Bls12_381>::prove(proving_key, circuit, &mut rng)?;
    Ok(proof)
}

/// Verify a memory safety proof
pub fn verify_memory_proof(
    proof: &Proof<Bls12_381>,
    verifying_key: &VerifyingKey<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<bool> {
    let pvk = prepare_verifying_key(verifying_key);
    Ok(Groth16::<Bls12_381>::verify_proof(&pvk, proof, public_inputs)?)
}
