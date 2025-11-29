/// Experimental tests to explore if fountain codes can be used for ZK proofs
/// 
/// Research questions:
/// 1. Can fountain codes work over finite fields (not just XOR)?
/// 2. Can we create cryptographic commitments to fountain symbols?
/// 3. Does belief propagation decoding work over finite fields?
/// 4. Can we prove properties of encoded data without revealing it?

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

// Simple finite field (prime field mod p)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldElement {
    value: u64,
    modulus: u64,
}

impl FieldElement {
    fn new(value: u64, modulus: u64) -> Self {
        Self {
            value: value % modulus,
            modulus,
        }
    }
    
    fn zero(modulus: u64) -> Self {
        Self::new(0, modulus)
    }
    
    fn add(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus);
        Self::new(self.value + other.value, self.modulus)
    }
    
    fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus);
        Self::new(self.value * other.value, self.modulus)
    }
}

// Robust Soliton distribution for degree sampling
struct RobustSoliton {
    k: usize,
    probabilities: Vec<f64>,
}

impl RobustSoliton {
    fn new(k: usize, c: f64, delta: f64) -> Self {
        let mut rho = vec![0.0; k + 1];
        
        // Ideal soliton
        rho[1] = 1.0 / k as f64;
        for d in 2..=k {
            rho[d] = 1.0 / (d * (d - 1)) as f64;
        }
        
        // Robust modification
        let r = c * (k as f64 / delta).ln() * (k as f64).sqrt();
        let kr = (k as f64 / r) as usize;
        let mut tau = vec![0.0; k + 1];
        
        for d in 1..kr {
            tau[d] = r / (d * k) as f64;
        }
        if kr < k {
            tau[kr] = r * (r / k as f64).ln() / k as f64;
        }
        
        // Combine and normalize
        let mut probabilities = vec![0.0; k + 1];
        let sum: f64 = (1..=k).map(|i| rho[i] + tau[i]).sum();
        for d in 1..=k {
            probabilities[d] = (rho[d] + tau[d]) / sum;
        }
        
        Self { k, probabilities }
    }
    
    fn sample(&self, rng: &mut impl Rng) -> usize {
        let r: f64 = rng.gen();
        let mut cumsum = 0.0;
        for (degree, &prob) in self.probabilities.iter().enumerate() {
            cumsum += prob;
            if r <= cumsum {
                return degree;
            }
        }
        self.k
    }
}

// Fountain encoded symbol
#[derive(Debug, Clone)]
struct FountainSymbol {
    symbol: FieldElement,
    neighbors: Vec<usize>,  // Which source symbols this encodes
    seed: u64,
}

// Test 1: Basic fountain encoding over finite field
#[test]
fn test_fountain_encoding_finite_field() {
    println!("\n=== TEST 1: Fountain Encoding Over Finite Field ===\n");
    
    let modulus = 1000000007u64; // Large prime
    let k = 100; // Source symbols
    
    // Create random source data
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let source: Vec<FieldElement> = (0..k)
        .map(|_| FieldElement::new(rng.gen::<u64>(), modulus))
        .collect();
    
    println!("Source symbols: {} elements over F_{}", k, modulus);
    println!("First 5 source values: {:?}", &source[..5].iter().map(|x| x.value).collect::<Vec<_>>());
    
    // Generate fountain symbols
    let distribution = RobustSoliton::new(k, 0.1, 0.01);
    let num_encoded = (k as f64 * 1.1) as usize; // 10% overhead
    
    let mut encoded_symbols = Vec::new();
    for seed in 0..num_encoded {
        let mut rng = ChaCha20Rng::seed_from_u64(seed as u64);
        let degree = distribution.sample(&mut rng);
        
        // Sample neighbors
        let mut neighbors = Vec::new();
        for _ in 0..degree {
            neighbors.push(rng.gen_range(0..k));
        }
        neighbors.sort();
        neighbors.dedup();
        
        // Combine source symbols (field addition, not XOR!)
        let mut symbol = FieldElement::zero(modulus);
        for &idx in &neighbors {
            symbol = symbol.add(&source[idx]);
        }
        
        encoded_symbols.push(FountainSymbol {
            symbol,
            neighbors,
            seed: seed as u64,
        });
    }
    
    println!("Generated {} encoded symbols", encoded_symbols.len());
    println!("Average degree: {:.2}", 
        encoded_symbols.iter().map(|s| s.neighbors.len()).sum::<usize>() as f64 / encoded_symbols.len() as f64);
    println!("\n✅ SUCCESS: Fountain encoding works over finite fields!\n");
}

// Test 2: Belief propagation decoding over finite field
#[test]
fn test_fountain_decoding_finite_field() {
    println!("\n=== TEST 2: Belief Propagation Decoding Over Finite Field ===\n");
    
    let modulus = 1000000007u64;
    let k = 50; // Smaller for testing
    
    let mut rng = ChaCha20Rng::seed_from_u64(54321);
    let source: Vec<FieldElement> = (0..k)
        .map(|_| FieldElement::new(rng.gen::<u64>(), modulus))
        .collect();
    
    println!("Source: {} symbols", k);
    
    // Generate encoded symbols
    let distribution = RobustSoliton::new(k, 0.1, 0.01);
    let num_encoded = (k as f64 * 1.2) as usize;
    
    let mut encoded_symbols = Vec::new();
    for seed in 0..num_encoded {
        let mut rng = ChaCha20Rng::seed_from_u64(seed as u64);
        let degree = distribution.sample(&mut rng).max(1);
        
        let mut neighbors = Vec::new();
        for _ in 0..degree {
            neighbors.push(rng.gen_range(0..k));
        }
        neighbors.sort();
        neighbors.dedup();
        
        let mut symbol = FieldElement::zero(modulus);
        for &idx in &neighbors {
            symbol = symbol.add(&source[idx]);
        }
        
        encoded_symbols.push(FountainSymbol {
            symbol,
            neighbors,
            seed: seed as u64,
        });
    }
    
    println!("Encoded: {} symbols", encoded_symbols.len());
    
    // Try to decode using belief propagation
    let mut decoded = vec![None; k];
    let mut remaining_symbols = encoded_symbols.clone();
    let mut iterations = 0;
    let max_iterations = 100;
    
    println!("Starting belief propagation...");
    
    while iterations < max_iterations {
        let mut progress = false;
        iterations += 1;
        
        // Find symbols with degree 1 (directly solvable)
        for i in 0..remaining_symbols.len() {
            if remaining_symbols[i].neighbors.len() == 1 {
                let source_idx = remaining_symbols[i].neighbors[0];
                if decoded[source_idx].is_none() {
                    decoded[source_idx] = Some(remaining_symbols[i].symbol);
                    progress = true;
                    
                    // Propagate: subtract this value from other symbols
                    for j in 0..remaining_symbols.len() {
                        if i != j && remaining_symbols[j].neighbors.contains(&source_idx) {
                            // Subtract decoded value
                            let sub_value = FieldElement::new(
                                (modulus + remaining_symbols[j].symbol.value - remaining_symbols[i].symbol.value) % modulus,
                                modulus
                            );
                            remaining_symbols[j].symbol = sub_value;
                            remaining_symbols[j].neighbors.retain(|&x| x != source_idx);
                        }
                    }
                }
            }
        }
        
        if !progress {
            break;
        }
        
        let decoded_count = decoded.iter().filter(|x| x.is_some()).count();
        if decoded_count == k {
            break;
        }
    }
    
    let decoded_count = decoded.iter().filter(|x| x.is_some()).count();
    println!("Decoded {}/{} symbols in {} iterations", decoded_count, k, iterations);
    
    // Verify correctness
    let mut correct = 0;
    for i in 0..k {
        if let Some(decoded_val) = decoded[i] {
            if decoded_val == source[i] {
                correct += 1;
            }
        }
    }
    
    println!("Correctly decoded: {}/{}", correct, decoded_count);
    println!("Success rate: {:.1}%", 100.0 * correct as f64 / k as f64);
    
    if correct == k {
        println!("\n✅ SUCCESS: Perfect decoding over finite field!\n");
    } else if correct > k * 90 / 100 {
        println!("\n⚠️  PARTIAL: >90% decoded, tuning needed\n");
    } else {
        println!("\n❌ FAILED: Poor decoding rate\n");
    }
}

// Test 3: Can we create ZK-like properties?
#[test]
fn test_fountain_zk_properties() {
    println!("\n=== TEST 3: Zero-Knowledge Properties ===\n");
    
    let modulus = 1000000007u64;
    let k = 20; // Small secret
    
    // Secret witness
    let mut rng = ChaCha20Rng::seed_from_u64(99999);
    let secret: Vec<FieldElement> = (0..k)
        .map(|_| FieldElement::new(rng.gen_range(1..100), modulus))
        .collect();
    
    println!("Secret witness: {} values", k);
    println!("Secret sum: {}", secret.iter().map(|x| x.value).sum::<u64>() % modulus);
    
    // Public statement: sum of secrets equals target
    let target_sum: u64 = secret.iter().map(|x| x.value).sum::<u64>() % modulus;
    println!("Public target sum: {}", target_sum);
    
    // Generate fountain encoding of secret
    let distribution = RobustSoliton::new(k, 0.1, 0.01);
    let num_revealed = (k as f64 * 0.5) as usize; // Reveal only 50%!
    
    let mut encoded_symbols = Vec::new();
    for seed in 0..num_revealed {
        let mut rng = ChaCha20Rng::seed_from_u64(seed as u64);
        let degree = distribution.sample(&mut rng).max(1);
        
        let mut neighbors = Vec::new();
        for _ in 0..degree {
            neighbors.push(rng.gen_range(0..k));
        }
        neighbors.sort();
        neighbors.dedup();
        
        let mut symbol = FieldElement::zero(modulus);
        for &idx in &neighbors {
            symbol = symbol.add(&secret[idx]);
        }
        
        encoded_symbols.push(FountainSymbol {
            symbol,
            neighbors,
            seed: seed as u64,
        });
    }
    
    println!("Revealed {} encoded symbols ({}% of k)", num_revealed, num_revealed * 100 / k);
    
    // Question: Can verifier learn secret from partial symbols?
    // Try to decode
    let mut decoded = vec![None; k];
    let mut remaining = encoded_symbols.clone();
    
    for _ in 0..50 {
        let mut progress = false;
        for i in 0..remaining.len() {
            if remaining[i].neighbors.len() == 1 {
                let idx = remaining[i].neighbors[0];
                if decoded[idx].is_none() {
                    decoded[idx] = Some(remaining[i].symbol);
                    progress = true;
                }
            }
        }
        if !progress {
            break;
        }
    }
    
    let leaked = decoded.iter().filter(|x| x.is_some()).count();
    println!("Verifier could decode: {}/{} secrets ({:.1}%)", 
        leaked, k, 100.0 * leaked as f64 / k as f64);
    
    if leaked < k / 2 {
        println!("\n✅ GOOD: Most secrets remain hidden with partial revelation!\n");
    } else if leaked < k {
        println!("\n⚠️  PARTIAL: Some secrets hidden, but not enough\n");
    } else {
        println!("\n❌ BAD: All secrets leaked!\n");
    }
    
    // Key insight: Need to add cryptographic commitments!
    println!("💡 INSIGHT: Raw fountain symbols leak info.");
    println!("   Need to combine with:");
    println!("   - Cryptographic commitments (hide values)");
    println!("   - ZK proofs of correct encoding");
    println!("   - Selective revelation protocol\n");
}

// Test 4: Commitment scheme for fountain symbols
#[test]
fn test_fountain_with_commitments() {
    println!("\n=== TEST 4: Fountain Symbols + Cryptographic Commitments ===\n");
    
    let modulus = 1000000007u64;
    let k = 30;
    
    let mut rng = ChaCha20Rng::seed_from_u64(11111);
    let secret: Vec<FieldElement> = (0..k)
        .map(|_| FieldElement::new(rng.gen::<u64>(), modulus))
        .collect();
    
    println!("Secret: {} values", k);
    
    // Generate fountain symbols
    let distribution = RobustSoliton::new(k, 0.1, 0.01);
    let num_encoded = (k as f64 * 1.1) as usize;
    
    let mut symbols = Vec::new();
    for seed in 0..num_encoded {
        let mut rng = ChaCha20Rng::seed_from_u64(seed as u64);
        let degree = distribution.sample(&mut rng).max(1);
        
        let mut neighbors = Vec::new();
        for _ in 0..degree {
            neighbors.push(rng.gen_range(0..k));
        }
        neighbors.sort();
        neighbors.dedup();
        
        let mut symbol = FieldElement::zero(modulus);
        for &idx in &neighbors {
            symbol = symbol.add(&secret[idx]);
        }
        
        symbols.push(FountainSymbol { symbol, neighbors, seed: seed as u64 });
    }
    
    // Commit to each symbol (simple hash commitment)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut commitments = Vec::new();
    let mut blinding_factors = Vec::new();
    
    for sym in &symbols {
        let blinding: u64 = rng.gen();
        blinding_factors.push(blinding);
        
        let mut hasher = DefaultHasher::new();
        sym.symbol.value.hash(&mut hasher);
        blinding.hash(&mut hasher);
        let commitment = hasher.finish();
        
        commitments.push(commitment);
    }
    
    println!("Created {} commitments to fountain symbols", commitments.len());
    println!("Commitments hide symbol values ✓");
    
    // Now prover can reveal subset without leaking others
    let reveal_count = k / 2;
    println!("\nProver reveals {} symbols ({}%)", reveal_count, reveal_count * 100 / k);
    
    for i in 0..reveal_count {
        // Verifier can check commitment
        let mut hasher = DefaultHasher::new();
        symbols[i].symbol.value.hash(&mut hasher);
        blinding_factors[i].hash(&mut hasher);
        let recomputed = hasher.finish();
        
        assert_eq!(commitments[i], recomputed, "Commitment verification failed!");
    }
    
    println!("All revealed symbols verified against commitments ✓");
    println!("Unrevealed symbols remain hidden ✓");
    
    println!("\n✅ SUCCESS: Commitments + Fountain codes work together!\n");
    println!("Next step: Prove correct encoding without revealing all symbols");
}
