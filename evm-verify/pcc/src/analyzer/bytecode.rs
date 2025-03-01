use crate::analyzer::Property;
use anyhow::Result;
use ethers::types::{Bytes, U256};

/// Bytecode vulnerability type
#[derive(Debug, Clone, PartialEq)]
pub enum VulnerabilityType {
    Reentrancy,
    IntegerOverflow,
    UnboundedLoop,
    UncheckedCall,
    AccessControl,
    OracleManipulation,
    MEVVulnerability,
    FrontRunning,
    PriceManipulation,
    BlockNumberDependence,
    UninitializedStorage,
    GovernanceVulnerability,
    BitMaskVulnerability,
    Other(String),
}

/// Bytecode vulnerability data
#[derive(Debug, Clone)]
pub struct VulnerabilityData {
    pub vulnerability_type: VulnerabilityType,
    pub offset: usize,
    pub description: String,
    pub severity: u8, // 1-5, with 5 being most severe
}

/// Bytecode safety proof data
#[derive(Debug, Clone)]
pub struct BytecodeSafetyProofData {
    pub is_safe: bool,
    pub vulnerabilities: Vec<VulnerabilityData>,
    pub gas_usage: U256,
    pub complexity: u32,
    pub bytecode_hash: Option<[u8; 32]>,
}

/// Bytecode safety property verifier
pub struct BytecodeSafetyProperty;

impl Property for BytecodeSafetyProperty {
    type Proof = BytecodeSafetyProofData;

    fn verify(&self, bytecode: &[u8]) -> Result<Self::Proof> {
        let mut bytecode_analyzer = BytecodeAnalyzer::new();
        
        // Analyze EVM bytecode
        bytecode_analyzer.analyze_bytecode(bytecode)?;
        
        let (vulnerabilities, gas_usage, complexity) = bytecode_analyzer.get_proof_data();
        let is_safe = vulnerabilities.is_empty();
        
        Ok(BytecodeSafetyProofData {
            is_safe,
            vulnerabilities,
            gas_usage,
            complexity,
            bytecode_hash: None,
        })
    }
}

/// Analyzer for detecting vulnerabilities in EVM bytecode
#[derive(Debug)]
pub struct BytecodeAnalyzer {
    vulnerabilities: Vec<VulnerabilityData>,
    gas_usage: U256,
    complexity: u32,
    jumpdests: Vec<usize>,
    stack: Vec<U256>,
    storage_reads: Vec<usize>,
    storage_writes: Vec<usize>,
    external_calls: Vec<usize>,
}

impl BytecodeAnalyzer {
    pub fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            gas_usage: U256::zero(),
            complexity: 0,
            jumpdests: Vec::new(),
            stack: Vec::new(),
            storage_reads: Vec::new(),
            storage_writes: Vec::new(),
            external_calls: Vec::new(),
        }
    }

    pub fn analyze_bytecode(&mut self, bytecode: &[u8]) -> Result<()> {
        let bytecode = Bytes::from(bytecode.to_vec());
        
        // First pass: collect all JUMPDEST instructions
        for i in 0..bytecode.len() {
            if bytecode[i] == 0x5B { // JUMPDEST
                self.jumpdests.push(i);
            }
        }
        
        // Second pass: analyze bytecode for vulnerabilities
        let mut i = 0;
        while i < bytecode.len() {
            let opcode = bytecode[i];
            
            // Track gas usage
            self.gas_usage += match opcode {
                0x00 => U256::from(0),  // STOP
                0x01..=0x0F => U256::from(3),  // Arithmetic operations
                0x10..=0x1F => U256::from(5),  // Comparison operations
                0x20..=0x3F => U256::from(3),  // SHA3, etc.
                0x40..=0x5F => U256::from(2),  // Block info, etc.
                0x60..=0x7F => U256::from(3),  // PUSH operations
                0x80..=0x8F => U256::from(3),  // DUP operations
                0x90..=0x9F => U256::from(3),  // SWAP operations
                0xA0..=0xAF => U256::from(10), // LOG operations
                0xF0..=0xFF => U256::from(100), // CREATE, CALL, etc.
                _ => U256::from(1),
            };
            
            // Track storage operations and external calls
            match opcode {
                0x54 => { // SLOAD - Storage read
                    self.storage_reads.push(i);
                },
                0x55 => { // SSTORE - Storage write
                    self.storage_writes.push(i);
                },
                0xF1 | 0xF2 | 0xF4 | 0xFA => { // CALL, CALLCODE, DELEGATECALL, STATICCALL
                    self.external_calls.push(i);
                },
                0x01 | 0x02 => { // ADD, MUL
                    // Check for integer overflow
                    // For simplicity, we'll just check if there's no overflow check before the operation
                    if i > 0 && bytecode[i-1] != 0x10 { // LT
                        self.vulnerabilities.push(VulnerabilityData {
                            vulnerability_type: VulnerabilityType::IntegerOverflow,
                            offset: i,
                            description: "Potential integer overflow detected".to_string(),
                            severity: 3,
                        });
                    }
                },
                0x56 | 0x57 => { // JUMP, JUMPI
                    // Check for valid jump destination
                    if let Some(dest) = self.stack.last() {
                        let dest_usize = dest.as_usize();
                        if !self.jumpdests.contains(&dest_usize) {
                            self.vulnerabilities.push(VulnerabilityData {
                                vulnerability_type: VulnerabilityType::Other("Invalid jump destination".to_string()),
                                offset: i,
                                description: "Jump to invalid destination".to_string(),
                                severity: 5,
                            });
                        }
                    }
                    self.complexity += 1; // Increase complexity for each jump
                },
                
                // PUSH operations
                0x60..=0x7F => {
                    let num_bytes = (opcode - 0x5F) as usize;
                    if i + num_bytes < bytecode.len() {
                        let mut value = U256::from(0);
                        for j in 0..num_bytes {
                            if i + 1 + j < bytecode.len() {
                                value = value * U256::from(256) + U256::from(bytecode[i + 1 + j]);
                            }
                        }
                        self.stack.push(value);
                        i += num_bytes;
                    }
                },
                
                // Add more vulnerability checks as needed
                
                _ => {
                    // For simplicity, we'll ignore other opcodes for now
                }
            }
            
            i += 1;
        }
        
        // After analyzing all opcodes, check for reentrancy pattern
        self.detect_reentrancy();
        
        Ok(())
    }

    // Add a new method to detect reentrancy vulnerabilities
    fn detect_reentrancy(&mut self) {
        // Check for reentrancy pattern: storage read -> external call -> storage write
        for &call_pos in &self.external_calls {
            // Find storage reads before the call
            let reads_before_call: Vec<_> = self.storage_reads.iter()
                .filter(|&&pos| pos < call_pos)
                .collect();
            
            // Find storage writes after the call
            let writes_after_call: Vec<_> = self.storage_writes.iter()
                .filter(|&&pos| pos > call_pos)
                .collect();
            
            // If we have both reads before and writes after, potential reentrancy
            if !reads_before_call.is_empty() && !writes_after_call.is_empty() {
                self.vulnerabilities.push(VulnerabilityData {
                    vulnerability_type: VulnerabilityType::Reentrancy,
                    offset: call_pos,
                    description: "Reentrancy vulnerability detected: storage read before external call followed by storage write after call".to_string(),
                    severity: 4,
                });
            }
        }
    }

    pub fn get_vulnerabilities(&self) -> &[VulnerabilityData] {
        &self.vulnerabilities
    }

    pub fn get_gas_usage(&self) -> U256 {
        self.gas_usage
    }

    pub fn get_complexity(&self) -> u32 {
        self.complexity
    }

    pub fn get_proof_data(&self) -> (Vec<VulnerabilityData>, U256, u32) {
        (
            self.vulnerabilities.clone(),
            self.gas_usage,
            self.complexity,
        )
    }
}
