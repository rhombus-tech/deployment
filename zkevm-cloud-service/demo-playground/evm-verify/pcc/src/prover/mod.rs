use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    Groth16,
    Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use anyhow::Result;

/// Generate proving and verifying keys for a circuit
pub fn generate_proving_key<C>(
    circuit: &C,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)>
where
    C: ConstraintSynthesizer<Fr> + Clone,
{
    let seed: [u8; 32] = [42; 32]; // Fixed seed for deterministic testing
    let mut rng = StdRng::from_seed(seed);
    let (params, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)?;
    Ok((params, vk))
}

/// Generate a proof for a circuit
pub fn generate_proof<C>(
    circuit: C,
    proving_key: &ProvingKey<Bn254>,
) -> Result<Proof<Bn254>>
where
    C: ConstraintSynthesizer<Fr>,
{
    let seed: [u8; 32] = [42; 32]; // Fixed seed for deterministic testing
    let mut rng = StdRng::from_seed(seed);
    let proof = Groth16::<Bn254>::prove(proving_key, circuit, &mut rng)?;
    Ok(proof)
}

/// Verify a memory safety proof
pub fn verify_memory_proof(
    proof: &Proof<Bn254>,
    verifying_key: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool> {
    // Use the correct verify method with correct parameter order
    Ok(Groth16::<Bn254>::verify(verifying_key, public_inputs, proof)?)
}

/// Verify a bytecode safety proof
pub fn verify_bytecode_proof(
    proof: &Proof<Bn254>,
    verifying_key: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool> {
    // Use the correct verify method with correct parameter order
    Ok(Groth16::<Bn254>::verify(verifying_key, public_inputs, proof)?)
}
