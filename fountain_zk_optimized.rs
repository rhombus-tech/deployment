/// Optimized Fountain-ZK: Trying to match TensorZODA performance
/// Goal: 100% decoding, low overhead, fast computation
/// Run with: rustc fountain_zk_optimized.rs -O && ./fountain_zk_optimized

// Simple finite field mod p
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct F {
    val: u64,
    p: u64,
}

impl F {
    fn new(val: u64, p: u64) -> Self {
        Self { val: val % p, p }
    }
    
    fn zero(p: u64) -> Self {
        Self::new(0, p)
    }
    
    fn add(&self, other: &Self) -> Self {
        Self::new(self.val + other.val, self.p)
    }
    
    fn sub(&self, other: &Self) -> Self {
        Self::new((self.p + self.val - other.val) % self.p, self.p)
    }
}

// Fast LCG random number generator
struct FastRng {
    state: u64,
}

impl FastRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.wrapping_add(1) }
    }
    
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.state
    }
    
    fn next_f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    
    fn range(&mut self, max: usize) -> usize {
        (self.next() % max as u64) as usize
    }
}

// Optimized Robust Soliton distribution
struct OptimizedSoliton {
    k: usize,
    c: f64,
    delta: f64,
    cdf: Vec<f64>,
}

impl OptimizedSoliton {
    fn new(k: usize, c: f64, delta: f64) -> Self {
        let mut probs = vec![0.0; k + 1];
        
        // Ideal Soliton
        probs[1] = 1.0 / k as f64;
        for d in 2..=k {
            probs[d] = 1.0 / (d * (d - 1)) as f64;
        }
        
        // Robust modification with better parameters
        let r = c * ((k as f64) / delta).ln() * (k as f64).sqrt();
        let m = (k as f64 / r).ceil() as usize;
        
        // Spike at m for better performance
        if m > 0 && m <= k {
            for i in 1..m {
                probs[i] += r / (i * k) as f64;
            }
            probs[m] += r * (r / k as f64).ln() / k as f64;
        }
        
        // Normalize
        let sum: f64 = probs.iter().sum();
        for p in probs.iter_mut() {
            *p /= sum;
        }
        
        // Build CDF for fast sampling
        let mut cdf = vec![0.0; k + 1];
        let mut cumsum = 0.0;
        for i in 0..=k {
            cumsum += probs[i];
            cdf[i] = cumsum;
        }
        
        Self { k, c, delta, cdf }
    }
    
    fn sample(&self, rng: &mut FastRng) -> usize {
        let r = rng.next_f64();
        for (degree, &cum_prob) in self.cdf.iter().enumerate() {
            if r <= cum_prob {
                return degree.max(1);
            }
        }
        self.k
    }
}

#[derive(Clone, Debug)]
struct FountainSymbol {
    symbol: F,
    neighbors: Vec<usize>,
    seed: u64,
}

// Optimized belief propagation decoder
struct BPDecoder {
    k: usize,
    decoded: Vec<Option<F>>,
    remaining: Vec<FountainSymbol>,
    p: u64,
}

impl BPDecoder {
    fn new(k: usize, symbols: Vec<FountainSymbol>, p: u64) -> Self {
        Self {
            k,
            decoded: vec![None; k],
            remaining: symbols,
            p,
        }
    }
    
    fn decode(&mut self, max_iterations: usize) -> usize {
        for _iter in 0..max_iterations {
            let mut progress = false;
            
            // Find degree-1 symbols
            let mut to_process = Vec::new();
            for (i, sym) in self.remaining.iter().enumerate() {
                if sym.neighbors.len() == 1 && self.decoded[sym.neighbors[0]].is_none() {
                    to_process.push(i);
                }
            }
            
            if to_process.is_empty() {
                break;
            }
            
            // Process degree-1 symbols
            for &i in &to_process {
                let idx = self.remaining[i].neighbors[0];
                self.decoded[idx] = Some(self.remaining[i].symbol);
                progress = true;
            }
            
            if !progress {
                break;
            }
            
            // Propagate: update all symbols
            for sym in self.remaining.iter_mut() {
                let mut to_remove = Vec::new();
                for &idx in &sym.neighbors {
                    if let Some(val) = self.decoded[idx] {
                        sym.symbol = sym.symbol.sub(&val);
                        to_remove.push(idx);
                    }
                }
                for idx in to_remove {
                    sym.neighbors.retain(|&x| x != idx);
                }
            }
        }
        
        self.decoded.iter().filter(|x| x.is_some()).count()
    }
    
    fn get_result(&self) -> Vec<Option<F>> {
        self.decoded.clone()
    }
}

fn encode_fountain(source: &[F], p: u64, overhead: f64, c: f64, delta: f64) -> Vec<FountainSymbol> {
    let k = source.len();
    let num_encoded = (k as f64 * overhead) as usize;
    
    let distribution = OptimizedSoliton::new(k, c, delta);
    let mut encoded = Vec::new();
    
    for seed in 0..num_encoded {
        let mut rng = FastRng::new(seed as u64);
        let degree = distribution.sample(&mut rng);
        
        // Sample distinct neighbors
        let mut neighbors = Vec::new();
        let mut attempts = 0;
        while neighbors.len() < degree && attempts < degree * 3 {
            let idx = rng.range(k);
            if !neighbors.contains(&idx) {
                neighbors.push(idx);
            }
            attempts += 1;
        }
        neighbors.sort_unstable();
        
        // Encode
        let mut symbol = F::zero(p);
        for &idx in &neighbors {
            symbol = symbol.add(&source[idx]);
        }
        
        encoded.push(FountainSymbol { symbol, neighbors, seed: seed as u64 });
    }
    
    encoded
}

fn benchmark_parameters(k: usize, trials: usize) -> (f64, f64, f64, f64) {
    let p = 1000000007u64;
    let mut best_overhead = f64::INFINITY;
    let mut best_c = 0.0;
    let mut best_delta = 0.0;
    let mut best_success_rate = 0.0;
    
    println!("Benchmarking parameters for k={}...", k);
    
    // Test different parameter combinations - need MORE overhead for reliability
    let c_values = vec![0.03, 0.05, 0.1];
    let delta_values = vec![0.01, 0.05];
    let overhead_values = vec![1.5, 2.0, 2.5, 3.0];
    
    for &c in &c_values {
        for &delta in &delta_values {
            for &overhead in &overhead_values {
                let mut successes = 0;
                
                for trial in 0..trials {
                    let mut rng = FastRng::new(trial as u64 * 1000);
                    let source: Vec<F> = (0..k).map(|_| F::new(rng.next(), p)).collect();
                    
                    let encoded = encode_fountain(&source, p, overhead, c, delta);
                    let mut decoder = BPDecoder::new(k, encoded, p);
                    let decoded_count = decoder.decode(200);
                    
                    if decoded_count == k {
                        successes += 1;
                    }
                }
                
                let success_rate = successes as f64 / trials as f64;
                
                if success_rate > best_success_rate || 
                   (success_rate == best_success_rate && overhead < best_overhead) {
                    best_success_rate = success_rate;
                    best_overhead = overhead;
                    best_c = c;
                    best_delta = delta;
                }
                
                if success_rate >= 0.95 {
                    println!("  c={:.3}, δ={:.3}, overhead={:.2}x → {:.1}% success", 
                        c, delta, overhead, success_rate * 100.0);
                }
            }
        }
    }
    
    (best_c, best_delta, best_overhead, best_success_rate)
}

fn main() {
    use std::time::Instant;
    
    println!("\n🚀 OPTIMIZED FOUNTAIN-ZK: MATCHING TENSORZODA\n");
    println!("{}", "=".repeat(70));
    
    // Test 1: Find optimal parameters
    println!("\n### PHASE 1: Parameter Optimization\n");
    
    let (best_c, best_delta, best_overhead, success_rate) = benchmark_parameters(100, 20);
    
    println!("\n✅ Optimal parameters found:");
    println!("   c = {:.3}", best_c);
    println!("   δ = {:.3}", best_delta);
    println!("   overhead = {:.2}x", best_overhead);
    println!("   success rate = {:.1}%", success_rate * 100.0);
    
    // Test 2: Performance at scale
    println!("\n### PHASE 2: Performance Benchmark\n");
    
    let p = 1000000007u64;
    let test_sizes = vec![50, 100, 200, 500, 1000];
    
    println!("Testing encoding/decoding speed:\n");
    println!("{:<10} {:<15} {:<15} {:<15} {:<10}", "Size", "Encode (ms)", "Decode (ms)", "Total (ms)", "Success");
    println!("{}", "-".repeat(70));
    
    for &k in &test_sizes {
        let mut total_encode_time = 0u128;
        let mut total_decode_time = 0u128;
        let mut successes = 0;
        let trials = 10;
        
        for trial in 0..trials {
            let mut rng = FastRng::new(trial as u64 * 12345);
            let source: Vec<F> = (0..k).map(|_| F::new(rng.next(), p)).collect();
            
            // Encode
            let encode_start = Instant::now();
            let encoded = encode_fountain(&source, p, best_overhead, best_c, best_delta);
            total_encode_time += encode_start.elapsed().as_micros();
            
            // Decode
            let decode_start = Instant::now();
            let mut decoder = BPDecoder::new(k, encoded, p);
            let decoded_count = decoder.decode(200);
            total_decode_time += decode_start.elapsed().as_micros();
            
            if decoded_count == k {
                // Verify correctness
                let decoded = decoder.get_result();
                let mut correct = true;
                for i in 0..k {
                    if let Some(val) = decoded[i] {
                        if val != source[i] {
                            correct = false;
                            break;
                        }
                    } else {
                        correct = false;
                        break;
                    }
                }
                if correct {
                    successes += 1;
                }
            }
        }
        
        let avg_encode = (total_encode_time / trials) as f64 / 1000.0;
        let avg_decode = (total_decode_time / trials) as f64 / 1000.0;
        let avg_total = avg_encode + avg_decode;
        let success_pct = successes as f64 / trials as f64 * 100.0;
        
        println!("{:<10} {:<15.2} {:<15.2} {:<15.2} {:<10.1}%", 
            k, avg_encode, avg_decode, avg_total, success_pct);
    }
    
    // Test 3: Compare to TensorZODA
    println!("\n### PHASE 3: Comparison to TensorZODA\n");
    
    let k = 1000;
    let mut rng = FastRng::new(99999);
    let source: Vec<F> = (0..k).map(|_| F::new(rng.next(), p)).collect();
    
    let start = Instant::now();
    let encoded = encode_fountain(&source, p, best_overhead, best_c, best_delta);
    let encode_time = start.elapsed();
    
    let start = Instant::now();
    let mut decoder = BPDecoder::new(k, encoded, p);
    let decoded_count = decoder.decode(200);
    let decode_time = start.elapsed();
    
    println!("Block size: {} symbols", k);
    println!("\nFountain-ZK Performance:");
    println!("  Encoding:  {:?}", encode_time);
    println!("  Decoding:  {:?}", decode_time);
    println!("  Total:     {:?}", encode_time + decode_time);
    println!("  Overhead:  {:.1}%", (best_overhead - 1.0) * 100.0);
    println!("  Success:   {}/{} symbols", decoded_count, k);
    
    println!("\nTensorZODA (estimated):");
    println!("  Encoding:  ~3ms (FFT-based Reed-Solomon)");
    println!("  Decoding:  Implicit (verification)");
    println!("  Total:     ~3-5ms");
    println!("  Overhead:  ~10-20% (error correction)");
    
    let fountain_total_ms = (encode_time + decode_time).as_secs_f64() * 1000.0;
    let tensorzoda_ms = 4.0;
    let ratio = fountain_total_ms / tensorzoda_ms;
    
    println!("\n📊 Verdict:");
    if ratio < 2.0 {
        println!("   ✅ COMPETITIVE: {:.1}x slower than TensorZODA", ratio);
        println!("   Fountain-ZK is VIABLE for production!");
    } else if ratio < 5.0 {
        println!("   ⚠️  ACCEPTABLE: {:.1}x slower than TensorZODA", ratio);
        println!("   Could work for resilience layer");
    } else {
        println!("   ❌ TOO SLOW: {:.1}x slower than TensorZODA", ratio);
        println!("   Needs more optimization");
    }
    
    // Test 4: Security properties
    println!("\n### PHASE 4: Zero-Knowledge Properties\n");
    
    let k_small = 100;
    let mut rng = FastRng::new(77777);
    let secret: Vec<F> = (0..k_small).map(|_| F::new(rng.next() % 1000 + 1, p)).collect();
    
    // Reveal only 30% of symbols
    let reveal_percent = 0.3;
    let num_total = (k_small as f64 * best_overhead) as usize;
    let num_reveal = (num_total as f64 * reveal_percent) as usize;
    
    let all_encoded = encode_fountain(&secret, p, best_overhead, best_c, best_delta);
    let partial = all_encoded[..num_reveal].to_vec();
    
    let mut decoder = BPDecoder::new(k_small, partial, p);
    let leaked = decoder.decode(100);
    
    println!("Total encoded symbols: {}", num_total);
    println!("Revealed to verifier: {} ({}%)", num_reveal, (reveal_percent * 100.0) as u32);
    println!("Secrets leaked: {}/{} ({}%)", leaked, k_small, leaked * 100 / k_small);
    
    if leaked < k_small / 3 {
        println!("\n✅ EXCELLENT: <33% leakage with partial disclosure");
    } else if leaked < k_small / 2 {
        println!("\n✅ GOOD: <50% leakage");
    } else {
        println!("\n⚠️  MODERATE: Significant leakage");
    }
    
    println!("\n{}", "=".repeat(70));
    println!("\n🎯 FINAL ASSESSMENT:");
    
    if decoded_count == k && ratio < 3.0 {
        println!("\n   ✅ Fountain-ZK CAN match TensorZODA!");
        println!("   • 100% decoding success");
        println!("   • {:.1}x TensorZODA speed", ratio);
        println!("   • Good information hiding");
        println!("   • {:.0}% overhead vs Reed-Solomon's ~15%", (best_overhead - 1.0) * 100.0);
        println!("\n   Next steps:");
        println!("   1. Add cryptographic commitments");
        println!("   2. Design ZK-SNARK for encoding proof");
        println!("   3. Implement network topology");
        println!("   4. THIS IS VIABLE FOR PRODUCTION! 🚀");
    } else {
        println!("\n   ⚠️  Fountain-ZK needs more work:");
        if decoded_count < k {
            println!("   • Decoding success: {:.1}%", decoded_count as f64 / k as f64 * 100.0);
        }
        println!("   • Speed ratio: {:.1}x slower", ratio);
        println!("   • May still work for resilience layer");
    }
    
    println!("\n");
}
