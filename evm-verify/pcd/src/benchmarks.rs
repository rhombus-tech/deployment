//! Benchmarks for comparing Groth16 vs. Tensor ZODA approaches
// Import criterion when the feature is enabled
#[cfg(feature = "criterion")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Ark imports
use ark_ff::Field;
use rand::RngCore;

use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, LinearCombination};

// Standard library imports

use std::clone::Clone;
use std::marker::PhantomData;
use rand::{thread_rng, Rng};

// Define error types that would be used in benchmarks
#[derive(Debug)]
pub enum TensorZODAError {
    InvalidDimensions,
    EncodingError,
    VerificationFailure,
}

// Import local modules
use crate::tensor_zoda::Matrix;



// Define a simple enum for circuit types
#[derive(Clone, Debug)]
pub enum CircuitType {
    ReentrancyDetection,
    IntegerOverflow,
    SignatureReplay,
}

// Create a simple test circuit from a CircuitType
#[derive(Clone)]
#[allow(dead_code)]
struct TestCircuit<F: Field> {
    circuit_type: CircuitType,
    _phantom: PhantomData<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for TestCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Very simple implementation - just creates a basic constraint
        // based on the circuit type
        match self.circuit_type {
            CircuitType::ReentrancyDetection => {
                // Create a simple constraint that represents reentrancy detection
                let a = cs.new_witness_variable(|| Ok(F::one()))?;
                let b = cs.new_witness_variable(|| Ok(F::one()))?;
                let c = cs.new_witness_variable(|| Ok(F::one() + F::one()))?;
                let lc_a = LinearCombination::<F>::from(a);
                let lc_b = LinearCombination::<F>::from(b);
                let lc_c = LinearCombination::<F>::from(c);
                cs.enforce_constraint(lc_a, lc_b, lc_c)?;
            }
            CircuitType::IntegerOverflow => {
                // Create a simple constraint that represents integer overflow check
                let a = cs.new_witness_variable(|| Ok(F::one()))?;
                let b = cs.new_witness_variable(|| Ok(F::one()))?;
                let c = cs.new_witness_variable(|| Ok(F::one() + F::one()))?;
                let lc_a = LinearCombination::<F>::from(a);
                let lc_b = LinearCombination::<F>::from(b);
                let lc_c = LinearCombination::<F>::from(c);
                cs.enforce_constraint(lc_a, lc_b, lc_c)?;
            }
            CircuitType::SignatureReplay => {
                // Create a simple constraint that represents signature replay check
                let a = cs.new_witness_variable(|| Ok(F::one()))?;
                let b = cs.new_witness_variable(|| Ok(F::one()))?;
                let c = cs.new_witness_variable(|| Ok(F::one() + F::one()))?;
                let lc_a = LinearCombination::<F>::from(a);
                let lc_b = LinearCombination::<F>::from(b);
                let lc_c = LinearCombination::<F>::from(c);
                cs.enforce_constraint(lc_a, lc_b, lc_c)?;
            }
        }
        Ok(())
    }
}

// Helper function to create a test circuit from a CircuitType
#[allow(dead_code)]
fn create_test_circuit<F: Field>(circuit_type: CircuitType, _n: usize) -> TestCircuit<F> {
    TestCircuit {
        circuit_type: circuit_type.clone(),
        _phantom: PhantomData,
    }
}

// Helper function to generate random test bytecode
#[allow(dead_code)]
fn generate_random_bytecode(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    (0..size).map(|_| rng.gen::<u8>()).collect()
}

// Generate random points for testing
#[allow(dead_code)]
fn generate_random_points<F: Field>(n: usize, rng: &mut impl RngCore) -> Vec<F> {
    (0..n).map(|_| F::rand(rng)).collect()
}

// Generate random matrix for testing
#[allow(dead_code)]
fn generate_random_matrix<F: Field>(rows: usize, cols: usize, _rng: &mut impl RngCore) -> Matrix<F> {
    let mut rng = thread_rng();
    let data = (0..rows)
        .map(|_| (0..cols).map(|_| F::rand(&mut rng)).collect())
        .collect();
    let golden_ratio = 1.618033988749895; // φ
    let rhombus_structure = crate::tensor_zoda::RhombusStructure::new(rows, cols, golden_ratio);
    Matrix { 
        rows, 
        cols, 
        data, 
        golden_ratio,
        rhombus_structure,
        optimization_enabled: true,
    }
}

// Move all benchmark functions under the criterion feature flag
#[cfg(feature = "criterion")]
mod benchmarks {
    use super::*;

    // Benchmark initialization and bytecode processing
    pub fn benchmark_initialization(c: &mut Criterion) {
        let mut group = c.benchmark_group("initialization");
        group.measurement_time(Duration::from_secs(10));
        
        // Test with various bytecode sizes
        for size in [1024, 4096, 16384].iter() {
            let bytecode = generate_random_bytecode(*size);
            
            // Benchmark Groth16-based approach
            group.bench_function(&format!("groth16_{}", size), |b| {
                b.iter(|| {
                    let mut accumulator = EVMAccumulator::<Fr>::new(128, false);
                    accumulator.initialize_with_bytecode(black_box(bytecode.clone())).unwrap()
                });
            });
            
            // Benchmark tensor ZODA approach
            group.bench_function(&format!("tensor_zoda_{}", size), |b| {
                b.iter(|| {
                    let field_size = 128;
                    let distance = 13;
                    let mut adapter = ZODAAccumulationAdapter::<Fr>::new(field_size, false);
                    adapter.initialize(black_box(bytecode.clone()), field_size, distance).unwrap()
                });
            });
        }
        
        group.finish();
    }

    // Benchmark proof generation
    pub fn benchmark_proof_generation(c: &mut Criterion) {
        let mut group = c.benchmark_group("proof_generation");
        group.measurement_time(Duration::from_secs(20));
        
        // Generate test bytecode
        let bytecode = generate_random_bytecode(4096);
        
        // Benchmark Groth16 proof generation
        group.bench_function("groth16", |b| {
            b.iter(|| {
                let mut accumulator = EVMAccumulator::<Fr>::new(128, false);
                let field_size = 128;
                let distance = 13;
                accumulator.initialize_with_bytecode(bytecode.clone()).unwrap();
                
                // Process a few circuit types
                // Create a simple circuit from the CircuitType for accumulation
                let circuit = create_test_circuit::<Fr>(CircuitType::ReentrancyDetection);
                accumulator.process_circuit(circuit).unwrap();
                // Create a simple circuit from the CircuitType for accumulation
                let circuit2 = create_test_circuit::<Fr>(CircuitType::IntegerOverflow);
                accumulator.process_circuit(circuit2).unwrap();
                
                // Finalize and get proof
                accumulator.finalize()
            });
        });
        
        // Benchmark tensor ZODA proof generation
        group.bench_function("reed_solomon_matrix", |b| {
            b.iter(|| {
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(128, 10);
                let m = black_box(100);
                let n = black_box(50);
                rs.generate_code_matrix(m, n)
            });
        });
        
        group.bench_function("polynomial_interpolation", |b| {
            b.iter(|| {
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(128, 10);
                let mut rng = thread_rng();
                // Convert Vec<Fr> to a Vec<(Fr, Fr)> for interpolation
                let points = generate_random_points::<Fr>(20, &mut rng);
                let points_with_indices: Vec<(Fr, Fr)> = points.iter().enumerate()
                    .map(|(i, &p)| (Fr::from(i as u64), p))
                    .collect();
                rs.interpolate_polynomial(&points_with_indices[..])
            });
        });
        
        group.bench_function("tensor_zoda", |b| {
            b.iter(|| {
                let field_size = 128;
                let distance = 13;
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(field_size, distance);
                let m = black_box(100);
                let n = black_box(50);
                rs.generate_code_matrix(m, n);
                let mut adapter = ZODAAccumulationAdapter::<Fr>::new(field_size, false);
                adapter.initialize(bytecode.clone(), field_size, distance).unwrap();
                
                // Process the same circuit types
                // Create a simple circuit from the CircuitType for accumulation
                let circuit = create_test_circuit::<Fr>(CircuitType::ReentrancyDetection);
                adapter.accumulate(circuit).unwrap();
                // Create a simple circuit from the CircuitType for accumulation
                let circuit2 = create_test_circuit::<Fr>(CircuitType::IntegerOverflow);
                adapter.accumulate(circuit2).unwrap();
                
                // Finalize and get proof
                adapter.finalize().unwrap();
                
                // Return success result
                Ok::<(), TensorZODAError>(())
            });
        });
        
        group.finish();
    }

    // Benchmark verification
    pub fn benchmark_verification(c: &mut Criterion) {
        let mut group = c.benchmark_group("verification");
        group.measurement_time(Duration::from_secs(10));
        
        // Generate test bytecode
        let bytecode = generate_random_bytecode(4096);
        
        // Setup Groth16 accumulator and generate proof
        let field_size = 128;
        let test_mode = false;
        let mut groth16_accumulator = EVMAccumulator::<Fr>::new(field_size, test_mode);
        groth16_accumulator.initialize_with_bytecode(bytecode.clone()).unwrap();
        // Create a simple circuit from the CircuitType for accumulation
        let circuit = create_test_circuit::<Fr>(CircuitType::ReentrancyDetection);
        groth16_accumulator.process_circuit(circuit).unwrap();
        groth16_accumulator.finalize().unwrap();
        
        // Setup tensor ZODA adapter and generate proof
        let field_size = 128;
        let distance = 13;
        let rs: ReedSolomon<Fr> = ReedSolomon::new(field_size, distance);
        let m = black_box(100);
        let n = black_box(50);
        rs.generate_code_matrix(m, n);
        let mut zoda_adapter = ZODAAccumulationAdapter::<Fr>::new(field_size, false);
        zoda_adapter.initialize(bytecode.clone(), field_size, distance).unwrap();
        // Create a simple circuit from the CircuitType for accumulation
        let circuit = create_test_circuit::<Fr>(CircuitType::ReentrancyDetection);
        zoda_adapter.accumulate(circuit).unwrap();
        zoda_adapter.finalize().unwrap();
        
        // Benchmark Groth16 verification
        group.bench_function("groth16_verify", |b| {
            b.iter(|| {
                // Verify proof with Groth16
                groth16_accumulator.verify_sampling(10).unwrap()
            });
        });
        
        // Benchmark tensor ZODA verification
        group.bench_function("tensor_zoda_verify", |b| {
            b.iter(|| {
                // Process vulnerabilities in a circuit - ignore the return value for benchmarking
                let _ = zoda_adapter.finalize().unwrap();
            });
        });
        
        group.finish();
    }

    // Benchmark tensor operations specifically
    pub fn benchmark_tensor_operations(c: &mut Criterion) {
        let mut group = c.benchmark_group("tensor_operations");
        group.measurement_time(Duration::from_secs(10));
        
        // Create a random matrix for tensor operations
        let matrix_size = 100;
        let input = generate_random_matrix::<Fr>(matrix_size, matrix_size);
        
        group.bench_function("matrix_multiply", |b| {
            b.iter(|| {
                let matrix1 = black_box(input.clone());
                let matrix2 = black_box(input.clone());
                matrix1.multiply(&matrix2)
            });
        });
        
        group.bench_function("tensor_zoda_encode", |b| {
            b.iter(|| {
                // Create a tensor ZODA instance
                let field_size = 128;
                let distance = 13;
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(field_size, distance);
                // Convert Vec<Vec<Fr>> to Matrix<Fr> explicitly
                let g_code_vec = rs.generate_code_matrix(128, 64);
                let g_prime_code_vec = rs.generate_code_matrix(128, 64);
                
                // Construct proper Matrix structs
                let g_code = Matrix {
                    rows: 128,
                    cols: 64,
                    data: g_code_vec,
                };
                
                let g_prime_code = Matrix {
                    rows: 128,
                    cols: 64,
                    data: g_prime_code_vec,
                };
                
                let mut tensor_zoda = TensorZODA::<Fr>::new(g_code, g_prime_code, distance, field_size);
                
                // Mock input data for encoding
                let input_data = generate_random_matrix::<Fr>(64, 64);
                
                // Process a circuit (any vulnerability detection)
                tensor_zoda.encode_input(&input_data)
            });
        });
        
        group.bench_function("tensor_zoda_sampling", |b| {
            b.iter(|| {
                // Create a tensor ZODA instance
                let field_size = 128;
                let distance = 13;
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(field_size, distance);
                // Convert Vec<Vec<Fr>> to Matrix<Fr> explicitly
                let g_code_vec = rs.generate_code_matrix(128, 64);
                let g_prime_code_vec = rs.generate_code_matrix(128, 64);
                
                // Construct proper Matrix structs
                let g_code = Matrix {
                    rows: 128,
                    cols: 64,
                    data: g_code_vec,
                };
                
                let g_prime_code = Matrix {
                    rows: 128,
                    cols: 64,
                    data: g_prime_code_vec,
                };
                
                let mut tensor_zoda = TensorZODA::<Fr>::new(g_code, g_prime_code, distance, field_size);
                
                // Generate random test data
                let mut rng = rand::thread_rng();
                let y_rows = generate_random_matrix::<Fr>(10, 128);
                let w_columns = generate_random_matrix::<Fr>(10, 128);
                let s_indices: Vec<usize> = (0..10).collect();
                let s_prime_indices: Vec<usize> = (0..10).collect();
                tensor_zoda.verify_sampling(&y_rows, &w_columns, &s_indices, &s_prime_indices, &mut rng)
            });
        });
        
        group.bench_function("reed_solomon_matrix", |b| {
            b.iter(|| {
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(128, 10);
                let m = black_box(100);
                let n = black_box(50);
                rs.generate_code_matrix(m, n)
            });
        });
        
        group.bench_function("polynomial_interpolation", |b| {
            b.iter(|| {
                let rs: ReedSolomon<Fr> = ReedSolomon::<Fr>::new(128, 10);
                let mut rng = thread_rng();
                // Convert Vec<Fr> to a Vec<(Fr, Fr)> for interpolation
                let points = generate_random_points::<Fr>(20, &mut rng);
                let points_with_indices: Vec<(Fr, Fr)> = points.iter().enumerate()
                    .map(|(i, &p)| (Fr::from(i as u64), p))
                    .collect();
                rs.interpolate_polynomial(&points_with_indices[..])
            });
        });
        
        group.finish();
    }
}

// Define criterion benchmarks (only when the criterion feature is enabled)
#[cfg(feature = "criterion")]
criterion_group!(
    benches,
    benchmarks::benchmark_initialization,
    benchmarks::benchmark_proof_generation,
    benchmarks::benchmark_verification,
    benchmarks::benchmark_tensor_operations
);

#[cfg(feature = "criterion")]
criterion_main!(benches);
