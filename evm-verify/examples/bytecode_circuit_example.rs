use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::One;
use ethers::types::Bytes;
use anyhow::Result;

use pcd::circuit_impl::PCDCircuit;

// Example EVM opcodes
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const CALL: u8 = 0xF1;
const POP: u8 = 0x50;
const PUSH1: u8 = 0x60;
const ISZERO: u8 = 0x15;
const JUMPI: u8 = 0x57;

// Example EVM bytecode with a reentrancy vulnerability
// This is a simplified example - in a real-world scenario, you would use actual EVM bytecode
fn create_vulnerable_bytecode() -> Bytes {
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // SLOAD (0x54) - Load from storage at key 0
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // CALL (0xF1) - Make an external call
    // POP (0x50) - Pop the result of CALL
    // PUSH1 0x01 (0x60, 0x01) - Push 1 onto the stack
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // SSTORE (0x55) - Store 1 at storage key 0
    
    Bytes::from(vec![
        PUSH1, 0x00, // PUSH1 0x00
        SLOAD,       // SLOAD
        PUSH1, 0x00, // PUSH1 0x00
        PUSH1, 0x00, // PUSH1 0x00
        PUSH1, 0x00, // PUSH1 0x00
        PUSH1, 0x00, // PUSH1 0x00
        CALL,        // CALL
        POP,         // POP
        PUSH1, 0x01, // PUSH1 0x01
        PUSH1, 0x00, // PUSH1 0x00
        SSTORE,      // SSTORE
    ])
}

// Example EVM bytecode without vulnerabilities
fn create_safe_bytecode() -> Bytes {
    // PUSH1 0x01 (0x60, 0x01) - Push 1 onto the stack
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // SSTORE (0x55) - Store 1 at storage key 0
    // PUSH1 0x00 (0x60, 0x00) - Push 0 onto the stack
    // SLOAD (0x54) - Load from storage at key 0
    
    Bytes::from(vec![
        PUSH1, 0x01, // PUSH1 0x01
        PUSH1, 0x00, // PUSH1 0x00
        SSTORE,      // SSTORE
        PUSH1, 0x00, // PUSH1 0x00
        SLOAD,       // SLOAD
    ])
}

// Create a circuit with in-circuit bytecode analysis
fn create_circuit_with_analysis(bytecode: Bytes) -> Result<PCDCircuit<Fr>> {
    // Create a circuit with the bytecode
    let circuit = PCDCircuit::<Fr>::new_with_analysis(
        bytecode,
        None,
        vec![Fr::from(42u32)],
    )?;
    
    // Print circuit info
    println!("Circuit created with {} bytecode bytes", circuit.bytecode.len());
    println!("Bytecode elements: {} field elements", circuit.bytecode_elements.len());
    
    Ok(circuit)
}

// Generate a proof for a circuit
fn generate_proof(circuit: PCDCircuit<Fr>) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>)> {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints
    <PCDCircuit<Fr> as ConstraintSynthesizer<Fr>>::generate_constraints(circuit.clone(), cs.clone())?;
    
    // Check if constraints are satisfied
    let is_satisfied = cs.is_satisfied()?;
    println!("Constraint system satisfied: {}", is_satisfied);
    println!("Number of constraints: {}", cs.num_constraints());
    
    // Generate a proving key and verification key
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)?;
    
    // Generate a proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;
    
    Ok((proof, vk))
}

// Verify a proof
fn verify_proof(proof: &Proof<Bn254>, vk: &VerifyingKey<Bn254>, public_inputs: &[Fr]) -> Result<bool> {
    let result = Groth16::<Bn254>::verify(vk, public_inputs, proof)?;
    Ok(result)
}

fn main() -> Result<()> {
    println!("EVM Bytecode Analysis in Circuits Example");
    println!("=========================================");
    
    // Create vulnerable bytecode
    println!("\nAnalyzing vulnerable bytecode...");
    let vulnerable_bytecode = create_vulnerable_bytecode();
    let vulnerable_circuit = create_circuit_with_analysis(vulnerable_bytecode)?;
    
    // Generate a proof for the vulnerable bytecode
    println!("\nGenerating proof for vulnerable bytecode...");
    let (vulnerable_proof, vulnerable_vk) = generate_proof(vulnerable_circuit)?;
    
    // Verify the proof
    println!("\nVerifying proof for vulnerable bytecode...");
    let public_inputs = vec![Fr::one(), Fr::from(42u32)];
    let vulnerable_result = verify_proof(&vulnerable_proof, &vulnerable_vk, &public_inputs)?;
    println!("Proof verification result: {}", vulnerable_result);
    
    // Create safe bytecode
    println!("\nAnalyzing safe bytecode...");
    let safe_bytecode = create_safe_bytecode();
    let safe_circuit = create_circuit_with_analysis(safe_bytecode)?;
    
    // Generate a proof for the safe bytecode
    println!("\nGenerating proof for safe bytecode...");
    let (safe_proof, safe_vk) = generate_proof(safe_circuit)?;
    
    // Verify the proof
    println!("\nVerifying proof for safe bytecode...");
    let safe_result = verify_proof(&safe_proof, &safe_vk, &public_inputs)?;
    println!("Proof verification result: {}", safe_result);
    
    Ok(())
}
