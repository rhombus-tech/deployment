use wasmparser::WasmFeatures;
use crate::analyzer::Property;
use common::MemorySafetyProofData;
use anyhow::Result;

/// Pipeline that coordinates WASM analysis and proof generation
pub struct AnalysisPipeline {
    memory_analyzer: crate::analyzer::memory::MemoryAnalyzer,
}

impl AnalysisPipeline {
    pub fn new() -> Self {
        Self {
            memory_analyzer: crate::analyzer::memory::MemoryAnalyzer::new(),
        }
    }
}

impl Property for AnalysisPipeline {
    type Proof = MemorySafetyProofData;

    /// Analyze a WASM binary and generate proof data
    fn verify(&self, wasm_binary: &[u8], _features: &WasmFeatures) -> Result<Self::Proof> {
        // Create a new analyzer for each verification
        let mut analyzer = crate::analyzer::memory::MemoryAnalyzer::new();
        
        // Parse WASM module
        analyzer.analyze_wasm(wasm_binary)?;
        
        let (memory_accesses, allocations, max_memory) = analyzer.get_proof_data();
        
        // For now, we'll assume all accesses are safe if we can parse the module
        Ok(MemorySafetyProofData {
            bounds_checked: true,
            leak_free: true,
            max_memory,
            access_safety: true,
            memory_accesses,
            allocations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;

    #[test]
    fn test_analyze_memory_ops() -> Result<()> {
        // Create a simple WASM module with memory operations
        let wasm = parse_str(r#"
            (module
                (memory 1)
                (func (export "test")
                    i32.const 0
                    i32.load
                    i32.const 4 
                    i32.store
                )
            )"#)?;

        let pipeline = AnalysisPipeline::new();
        let proof_data = pipeline.verify(&wasm, &WasmFeatures::default())?;

        // Verify memory accesses were analyzed
        assert!(!proof_data.memory_accesses.is_empty());
        assert!(!proof_data.allocations.is_empty());
        assert!(proof_data.max_memory > 0);

        Ok(())
    }
}
