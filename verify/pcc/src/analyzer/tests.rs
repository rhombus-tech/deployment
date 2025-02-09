use super::*;
use wasmparser::WasmFeatures;
use wat::parse_str;

// Helper to create WASM module from WAT
fn create_test_module(wat: &str) -> Vec<u8> {
    parse_str(wat).expect("Failed to parse WAT")
}

#[test]
fn test_memory_safety_basic() {
    let wat = r#"
        (module
            (memory 1)
            (func (export "test")
                i32.const 0    ;; address
                i32.const 42   ;; value
                i32.store      ;; store at address 0
                
                i32.const 0    ;; address
                i32.load       ;; load from address 0
                drop
            )
        )"#;
    
    let wasm = create_test_module(wat);
    let property = memory::MemorySafetyProperty;
    let proof = property.verify(&wasm, &WasmFeatures::default())
        .expect("Verification failed");
        
    assert!(proof.bounds_checked, "Memory access should be bounds checked");
    assert!(proof.leak_free, "No memory leaks should be detected");
    assert!(proof.access_safety, "Memory access should be safe");
}

#[test]
fn test_memory_safety_growth() {
    let wat = r#"
        (module
            (memory 1 2)  ;; Initial 1 page, max 2 pages
            (func (export "test")
                i32.const 1
                memory.grow    ;; Grow by 1 page
                drop
            )
        )"#;
    
    let wasm = create_test_module(wat);
    let property = memory::MemorySafetyProperty;
    let proof = property.verify(&wasm, &WasmFeatures::default())
        .expect("Verification failed");
        
    assert_eq!(proof.max_memory, 2, "Maximum memory should be 2 pages");
}

#[test]
fn test_proof_serialization() {
    let wat = r#"
        (module
            (memory 1)
            (func (export "test")
                i32.const 0
                i32.const 42
                i32.store
            )
        )"#;
    
    let wasm = create_test_module(wat);
    let property = memory::MemorySafetyProperty;
    let proof = property.verify(&wasm, &WasmFeatures::default())
        .expect("Verification failed");
        
    // Convert to proof data
    let proof_data = proof.into_proof_data()
        .expect("Failed to convert to proof data");
        
    // Serialize
    let mut bytes = Vec::new();
    proof_data.serialize(&mut bytes)
        .expect("Failed to serialize");
        
    // Deserialize
    let deserialized = MemorySafetyProofData::deserialize(&bytes[..])
        .expect("Failed to deserialize");
        
    assert_eq!(deserialized.bounds_checked, proof_data.bounds_checked);
    assert_eq!(deserialized.leak_free, proof_data.leak_free);
    assert_eq!(deserialized.max_memory, proof_data.max_memory);
    assert_eq!(deserialized.access_safety, proof_data.access_safety);
}

#[test]
fn test_memory_safety_circuit() {
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    
    let wat = r#"
        (module
            (memory 1)
            (func (export "test")
                i32.const 0
                i32.const 42
                i32.store
            )
        )"#;
    
    let wasm = create_test_module(wat);
    let property = memory::MemorySafetyProperty;
    let proof = property.verify(&wasm, &WasmFeatures::default())
        .expect("Verification failed");
        
    // Convert to proof data and serialize
    let proof_data = proof.into_proof_data()
        .expect("Failed to convert to proof data");
    let mut bytes = Vec::new();
    proof_data.serialize(&mut bytes)
        .expect("Failed to serialize");
        
    // Create and verify circuit
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = MemorySafetyCircuit::<Fr>::from_proof(&bytes)
        .expect("Failed to create circuit");
        
    circuit.generate_constraints(cs.clone())
        .expect("Failed to generate constraints");
        
    assert!(cs.is_satisfied().expect("Failed to check constraints"));
}
