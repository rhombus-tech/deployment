use anyhow::{Result, anyhow};
use crate::analyzer::{
    memory::MemoryAnalyzer,
    bytecode::BytecodeAnalyzer,
};

/// The AnalysisPipeline combines multiple analyzers to perform a comprehensive
/// security analysis of EVM bytecode.
pub struct AnalysisPipeline {
    memory_analyzer: MemoryAnalyzer,
    bytecode_analyzer: BytecodeAnalyzer,
}

impl AnalysisPipeline {
    /// Create a new analysis pipeline
    pub fn new() -> Self {
        Self {
            memory_analyzer: MemoryAnalyzer::new(),
            bytecode_analyzer: BytecodeAnalyzer::new(),
        }
    }
    
    /// Run the full analysis pipeline on a bytecode
    pub fn analyze(&mut self, bytecode: &[u8]) -> Result<()> {
        // Run memory safety analysis
        self.memory_analyzer.analyze_bytecode(bytecode)?;
        
        // Run bytecode vulnerability analysis
        self.bytecode_analyzer.analyze_bytecode(bytecode)?;
        
        Ok(())
    }
    
    /// Get the memory analyzer
    pub fn memory_analyzer(&self) -> &MemoryAnalyzer {
        &self.memory_analyzer
    }
    
    /// Get the bytecode analyzer
    pub fn bytecode_analyzer(&self) -> &BytecodeAnalyzer {
        &self.bytecode_analyzer
    }
    
    /// Check if the bytecode is safe
    pub fn is_safe(&self) -> bool {
        // Bytecode is considered safe if it has no vulnerabilities
        self.bytecode_analyzer.get_vulnerabilities().is_empty()
    }
    
    /// Get a summary of the analysis results
    pub fn get_summary(&self) -> String {
        let vulnerabilities = self.bytecode_analyzer.get_vulnerabilities();
        let memory_accesses = self.memory_analyzer.get_memory_accesses();
        let allocations = self.memory_analyzer.get_allocations();
        
        let mut summary = String::new();
        
        summary.push_str(&format!("Analysis Summary:\n"));
        summary.push_str(&format!("- Memory accesses: {}\n", memory_accesses.len()));
        summary.push_str(&format!("- Memory allocations: {}\n", allocations.len()));
        summary.push_str(&format!("- Vulnerabilities found: {}\n", vulnerabilities.len()));
        summary.push_str(&format!("- Gas usage estimate: {}\n", self.bytecode_analyzer.get_gas_usage()));
        summary.push_str(&format!("- Code complexity: {}\n", self.bytecode_analyzer.get_complexity()));
        
        if !vulnerabilities.is_empty() {
            summary.push_str("\nVulnerabilities:\n");
            for (i, vuln) in vulnerabilities.iter().enumerate() {
                summary.push_str(&format!("{}. {} (offset: {}, severity: {})\n   {}\n", 
                    i + 1,
                    format!("{:?}", vuln.vulnerability_type),
                    vuln.offset,
                    vuln.severity,
                    vuln.description
                ));
            }
        }
        
        summary
    }
    
    /// Generate a proof for the given bytecode
    pub fn generate_proof(&self, _bytecode: &[u8]) -> Result<()> {
        // This would generate ZK proofs using the circuits
        // For now, we'll just return a placeholder
        
        if !self.is_safe() {
            return Err(anyhow!("Cannot generate proof for unsafe bytecode"));
        }
        
        // In a real implementation, this would:
        // 1. Create circuit instances
        // 2. Generate proofs using the prover module
        // 3. Return the proof data
        
        Ok(())
    }
}
