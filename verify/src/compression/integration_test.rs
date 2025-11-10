use super::*;
use crate::proofs::{MemorySafetyProperty, Property};
use wasmparser::WasmFeatures;
use anyhow::Result;

/// Integration test demonstrating Williams compression with WASM verification
pub fn test_williams_compression_pipeline() -> Result<()> {
    println!("🚀 Testing Williams Compression + WASM Verification Pipeline");
    
    // 1. Create test WASM contract
    let test_wasm = create_test_wasm_contract();
    println!("📝 Created test WASM contract ({} bytes)", test_wasm.len());
    
    // 2. Verify original WASM safety properties
    let memory_property = MemorySafetyProperty::new();
    let features = WasmFeatures::default();
    let original_proof = memory_property.verify(&test_wasm, &features)?;
    
    println!("✅ Original WASM safety verification:");
    println!("   • Bounds checked: {}", original_proof.bounds_checked);
    println!("   • Leak free: {}", original_proof.leak_free);
    println!("   • Access safety: {}", original_proof.access_safety);
    
    // 3. Initialize Williams compressor with ZK setup
    let mut williams_verifier = WilliamsVerifier::new();
    williams_verifier.setup_keys()?;
    println!("🔑 Initialized ZK proof system");
    
    // 4. Compress WASM with integrity proofs
    let compressed_proof = williams_verifier.compress_and_verify(&test_wasm, &features)?;
    
    println!("📦 Compression results:");
    println!("   • Original size: {} bytes", compressed_proof.analysis.original_size);
    println!("   • Compressed size: {} bytes", compressed_proof.analysis.compressed_size);
    println!("   • Compression ratio: {:.2}x", compressed_proof.analysis.compression_ratio);
    println!("   • Compression time: {} ms", compressed_proof.analysis.compression_time_ms);
    println!("   • Decompression time: {} ms", compressed_proof.analysis.decompression_time_ms);
    
    // 5. Generate TEE attestation
    let tee_attestation = williams_verifier.generate_tee_attestation(&compressed_proof)?;
    println!("🔒 Generated TEE attestation");
    println!("   • Attestation hash: {:02x?}", &tee_attestation.attestation_hash[..8]);
    println!("   • Timestamp: {}", tee_attestation.timestamp);
    
    // 6. Verify compressed WASM with proofs
    let verification_result = williams_verifier.verify_compressed_wasm(
        &compressed_proof, 
        &tee_attestation
    )?;
    
    println!("🔍 Verification results:");
    println!("   • Compression integrity: {}", verification_result);
    println!("   • Safety properties preserved: {}", compressed_proof.analysis.safety_properties_preserved);
    println!("   • Memory layout preserved: {}", compressed_proof.analysis.memory_layout_preserved);
    println!("   • Execution semantics preserved: {}", compressed_proof.analysis.execution_semantics_preserved);
    
    // 7. Performance comparison
    println!("\n📊 Performance Analysis:");
    println!("   • Space savings: {:.1}%", 
        (1.0 - (compressed_proof.analysis.compressed_size as f64 / compressed_proof.analysis.original_size as f64)) * 100.0);
    
    let bandwidth_savings = compressed_proof.analysis.original_size - compressed_proof.analysis.compressed_size;
    println!("   • Bandwidth savings: {} bytes per deployment", bandwidth_savings);
    
    // 8. TEE memory savings calculation
    let memory_savings_per_keep = bandwidth_savings;
    let keeps_per_region = 100; // Typical Enarx deployment
    let total_memory_savings = memory_savings_per_keep * keeps_per_region;
    
    println!("   • Memory savings per Enarx keep: {} bytes", memory_savings_per_keep);
    println!("   • Total memory savings (100 keeps): {} KB", total_memory_savings / 1024);
    
    if verification_result && 
       compressed_proof.analysis.safety_properties_preserved &&
       compressed_proof.analysis.compression_ratio >= 1.25 {
        println!("\n🎉 SUCCESS: Williams compression pipeline fully verified!");
        println!("   Ready for production deployment with Enarx keeps");
        Ok(())
    } else {
        anyhow::bail!("❌ Verification failed - compression pipeline not ready")
    }
}

/// Create a realistic WASM contract for testing
fn create_test_wasm_contract() -> Vec<u8> {
    // WASM module with realistic patterns that Williams compression can optimize
    let mut wasm = Vec::new();
    
    // WASM magic number and version
    wasm.extend_from_slice(b"\x00asm");
    wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    
    // Type section - function signatures
    wasm.push(0x01); // Type section ID
    wasm.push(0x07); // Section size
    wasm.push(0x01); // 1 type
    wasm.push(0x60); // Function type
    wasm.push(0x02); // 2 parameters
    wasm.push(0x7f); // i32
    wasm.push(0x7f); // i32
    wasm.push(0x01); // 1 result
    wasm.push(0x7f); // i32
    
    // Function section
    wasm.push(0x03); // Function section ID  
    wasm.push(0x02); // Section size
    wasm.push(0x01); // 1 function
    wasm.push(0x00); // Type 0
    
    // Memory section
    wasm.push(0x05); // Memory section ID
    wasm.push(0x03); // Section size
    wasm.push(0x01); // 1 memory
    wasm.push(0x00); // No maximum
    wasm.push(0x01); // Initial size: 1 page
    
    // Export section
    wasm.push(0x07); // Export section ID
    wasm.push(0x07); // Section size
    wasm.push(0x01); // 1 export
    wasm.push(0x03); // Name length
    wasm.extend_from_slice(b"add"); // Export name
    wasm.push(0x00); // Function export
    wasm.push(0x00); // Function index
    
    // Code section with repeated patterns Williams can compress
    wasm.push(0x0a); // Code section ID
    wasm.push(0x20); // Section size (will be longer due to repetition)
    wasm.push(0x01); // 1 function body
    wasm.push(0x1e); // Function body size
    wasm.push(0x00); // 0 locals
    
    // Function body with patterns Williams can compress
    for _ in 0..5 {
        wasm.push(0x20); // local.get
        wasm.push(0x00); // index 0
        wasm.push(0x20); // local.get  
        wasm.push(0x01); // index 1
    }
    
    wasm.push(0x6a); // i32.add
    
    // Add some zero padding (compression target)
    wasm.extend(vec![0x00; 50]);
    
    wasm.push(0x0b); // end
    
    wasm
}

/// Run comprehensive compression benchmarks
pub fn benchmark_williams_compression() -> Result<()> {
    println!("\n🏁 Running Williams Compression Benchmarks");
    
    let compressor = WilliamsCompressor::new();
    
    // Test different contract sizes
    let test_sizes = vec![1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB
    
    for &size in &test_sizes {
        let test_data = generate_wasm_like_data(size);
        
        let start = std::time::Instant::now();
        let compressed = compressor.compress(&test_data)?;
        let compression_time = start.elapsed();
        
        let start = std::time::Instant::now();
        let decompressed = compressor.decompress(&compressed)?;
        let decompression_time = start.elapsed();
        
        assert_eq!(test_data, decompressed);
        
        let ratio = test_data.len() as f64 / compressed.len() as f64;
        
        println!("   📋 Size: {} KB", size / 1024);
        println!("      • Compression: {:.2}x ({:.1}% savings)", ratio, (1.0 - 1.0/ratio) * 100.0);
        println!("      • Compression time: {:.2} ms", compression_time.as_millis());
        println!("      • Decompression time: {:.2} ms", decompression_time.as_millis());
        println!("      • Throughput: {:.1} MB/s", (size as f64 / 1024.0 / 1024.0) / compression_time.as_secs_f64());
    }
    
    Ok(())
}

fn generate_wasm_like_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    
    // WASM magic
    data.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    
    // Fill with patterns typical in WASM
    let patterns = vec![
        vec![0x20, 0x00], // local.get 0
        vec![0x20, 0x01], // local.get 1
        vec![0x6a],       // i32.add
        vec![0x41, 0x00], // i32.const 0
        vec![0x0b],       // end
    ];
    
    while data.len() < size {
        let pattern = &patterns[data.len() % patterns.len()];
        data.extend_from_slice(pattern);
        
        // Add some zero padding occasionally
        if data.len() % 100 == 0 {
            data.extend(vec![0x00; 10]);
        }
    }
    
    data.truncate(size);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_pipeline() {
        test_williams_compression_pipeline().expect("Integration test failed");
    }
    
    #[test] 
    fn test_compression_benchmarks() {
        benchmark_williams_compression().expect("Benchmark test failed");
    }
}
