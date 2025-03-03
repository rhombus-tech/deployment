use crate::analyzer::Property;
use anyhow::Result;
use ethers::types::{Bytes, U256};

/// Bytecode vulnerability type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
    Reentrancy,
    IntegerOverflow,
    UnboundedLoop,
    UncheckedCall,
    AccessControl,
    SelfDestruct,
    OracleManipulation,
    MevVulnerability,
    FrontRunning,
    PriceManipulation,
    BlockNumberDependence,
    UninitializedStorage,
    ProxyVulnerability,
    GasGriefing,
    WeakRandomness,
    GovernanceVulnerability,
    BitmaskVulnerability,
    PrecisionLoss,
    CentralizedControl,
    InsufficientSlippageProtection,
    TimelockIssue,
    UncheckedReturnValue,
    CrossContractReentrancy,
    Other(u8),
}

impl VulnerabilityType {
    pub fn from_api_vulnerability_type(api_vulnerability_type: crate::api::VulnerabilityType) -> Self {
        match api_vulnerability_type {
            crate::api::VulnerabilityType::Reentrancy => Self::Reentrancy,
            crate::api::VulnerabilityType::IntegerOverflow => Self::IntegerOverflow,
            crate::api::VulnerabilityType::UnboundedLoop => Self::UnboundedLoop,
            crate::api::VulnerabilityType::UncheckedCall => Self::UncheckedCall,
            crate::api::VulnerabilityType::AccessControl => Self::AccessControl,
            crate::api::VulnerabilityType::SelfDestruct => Self::SelfDestruct,
            crate::api::VulnerabilityType::OracleManipulation => Self::OracleManipulation,
            crate::api::VulnerabilityType::MevVulnerability => Self::MevVulnerability,
            crate::api::VulnerabilityType::FrontRunning => Self::FrontRunning,
            crate::api::VulnerabilityType::PriceManipulation => Self::PriceManipulation,
            crate::api::VulnerabilityType::BlockNumberDependence => Self::BlockNumberDependence,
            crate::api::VulnerabilityType::UninitializedStorage => Self::UninitializedStorage,
            crate::api::VulnerabilityType::ProxyVulnerability => Self::ProxyVulnerability,
            crate::api::VulnerabilityType::GasGriefing => Self::GasGriefing,
            crate::api::VulnerabilityType::WeakRandomness => Self::WeakRandomness,
            crate::api::VulnerabilityType::GovernanceVulnerability => Self::GovernanceVulnerability,
            crate::api::VulnerabilityType::BitmaskVulnerability => Self::BitmaskVulnerability,
            crate::api::VulnerabilityType::PrecisionLoss => Self::PrecisionLoss,
            crate::api::VulnerabilityType::CentralizedControl => Self::CentralizedControl,
            crate::api::VulnerabilityType::InsufficientSlippageProtection => Self::InsufficientSlippageProtection,
            crate::api::VulnerabilityType::TimelockIssue => Self::TimelockIssue,
            crate::api::VulnerabilityType::UncheckedReturnValue => Self::UncheckedReturnValue,
            crate::api::VulnerabilityType::CrossContractReentrancy => Self::CrossContractReentrancy,
            crate::api::VulnerabilityType::Other(val) => Self::Other(val),
            crate::api::VulnerabilityType::Unknown => Self::Other(255),
        }
    }
}

/// Bytecode vulnerability data
#[derive(Debug, Clone)]
pub struct VulnerabilityData {
    pub vulnerability_type: VulnerabilityType,
    pub offset: usize,
    pub description: String,
    pub severity: u8,
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
    bytecode: Bytes,
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
            bytecode: Bytes::new(),
        }
    }

    pub fn analyze_bytecode(&mut self, bytecode: &[u8]) -> Result<()> {
        self.bytecode = Bytes::from(bytecode.to_vec());
        
        // First pass: collect all JUMPDEST instructions
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x5B { // JUMPDEST
                self.jumpdests.push(i);
            }
        }
        
        // Second pass: analyze bytecode for vulnerabilities
        let mut i = 0;
        while i < self.bytecode.len() {
            let opcode = self.bytecode[i];
            
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
                    if i > 0 && self.bytecode[i-1] != 0x10 { // LT
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
                                vulnerability_type: VulnerabilityType::Other(255),
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
                    if i + num_bytes < self.bytecode.len() {
                        let mut value = U256::from(0);
                        for j in 0..num_bytes {
                            if i + 1 + j < self.bytecode.len() {
                                value = value * U256::from(256) + U256::from(self.bytecode[i + 1 + j]);
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
        self.detect_cross_contract_reentrancy();
        self.detect_bitmask_vulnerability();
        
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

    // Add a new method to detect cross-contract reentrancy vulnerabilities
    fn detect_cross_contract_reentrancy(&mut self) {
        // Check for cross-contract reentrancy pattern:
        // 1. Multiple external calls to different contracts
        // 2. State changes after calls
        // 3. Shared state access patterns

        // First, identify if we have multiple external calls
        if self.external_calls.len() < 2 {
            return; // Need at least two calls for cross-contract reentrancy
        }

        // Track contract addresses being called (approximation based on bytecode patterns)
        let mut different_contract_calls = false;
        let mut contract_addresses = Vec::new();

        for &call_pos in &self.external_calls {
            // In EVM, the contract address is typically loaded onto the stack before the CALL
            // We'll look for PUSH20 (0x73) opcodes before calls as a heuristic
            // This is a simplification - in real analysis we'd track stack state
            
            // Look up to 30 opcodes before the call for a PUSH20
            let start_pos = if call_pos > 30 { call_pos - 30 } else { 0 };
            for i in start_pos..call_pos {
                if i < self.bytecode.len() && self.bytecode[i] == 0x73 { // PUSH20
                    // Extract the 20 bytes after PUSH20 as the address
                    if i + 20 < self.bytecode.len() {
                        let address = &self.bytecode[i+1..i+21];
                        
                        // Check if we've seen this address before
                        let mut found = false;
                        for addr in &contract_addresses {
                            if addr == address {
                                found = true;
                                break;
                            }
                        }
                        
                        if !found {
                            contract_addresses.push(address.to_vec());
                            
                            // If we have at least two different addresses, set the flag
                            if contract_addresses.len() >= 2 {
                                different_contract_calls = true;
                                break;
                            }
                        }
                    }
                }
            }
            
            if different_contract_calls {
                break;
            }
        }

        // If we don't have calls to different contracts, not a cross-contract issue
        if !different_contract_calls {
            return;
        }
        
        // For debugging
        println!("Analyzer cross-contract reentrancy detection:");
        println!("  Storage reads: {}", self.storage_reads.len());
        println!("  External calls: {}", self.external_calls.len());
        println!("  Storage writes: {}", self.storage_writes.len());
        println!("  Different contract addresses: {}", contract_addresses.len());

        // Now check for state changes after calls (similar to regular reentrancy)
        let mut has_vulnerability = false;
        for &call_pos in &self.external_calls {
            // Find storage reads before the call
            let reads_before_call: Vec<_> = self.storage_reads.iter()
                .filter(|&&pos| pos < call_pos)
                .collect();
            
            // Find storage writes after the call
            let writes_after_call: Vec<_> = self.storage_writes.iter()
                .filter(|&&pos| pos > call_pos)
                .collect();
            
            // If we have both reads before and writes after, and multiple contract calls,
            // this is a potential cross-contract reentrancy vulnerability
            if !reads_before_call.is_empty() && !writes_after_call.is_empty() {
                has_vulnerability = true;
                break;
            }
        }
        
        // If we have the pattern, report the vulnerability
        if has_vulnerability {
            self.vulnerabilities.push(VulnerabilityData {
                vulnerability_type: VulnerabilityType::CrossContractReentrancy,
                offset: self.external_calls[0], // Report at the first call
                description: "Cross-contract reentrancy vulnerability detected: multiple contract calls with state changes".to_string(),
                severity: 5, // Higher severity than regular reentrancy
            });
        }
    }

    fn detect_bitmask_vulnerability(&mut self) {
        // Bitmask vulnerabilities occur when bit manipulation operations are used incorrectly,
        // potentially leading to unexpected behavior or security issues.
        
        // Common patterns to look for:
        // 1. Improper bit masking (AND, OR, XOR, NOT operations)
        // 2. Incorrect bit shifting (SHL, SHR)
        // 3. Inconsistent bit manipulation patterns
        
        // Track bit manipulation operations
        let mut bit_ops = Vec::new();
        
        // EVM opcodes for bit operations
        const AND: u8 = 0x16;  // Bitwise AND
        const OR: u8 = 0x17;   // Bitwise OR
        const XOR: u8 = 0x18;  // Bitwise XOR
        const NOT: u8 = 0x19;  // Bitwise NOT
        const SHL: u8 = 0x1b;  // Shift left
        const SHR: u8 = 0x1c;  // Logical shift right
        const SAR: u8 = 0x1d;  // Arithmetic shift right
        
        // Scan bytecode for bit manipulation operations
        for i in 0..self.bytecode.len() {
            let opcode = self.bytecode[i];
            
            // Check if this is a bit manipulation opcode
            if opcode == AND || opcode == OR || opcode == XOR || opcode == NOT || 
               opcode == SHL || opcode == SHR || opcode == SAR {
                bit_ops.push((i, opcode));
            }
        }
        
        // If we don't have enough bit operations, no vulnerability
        if bit_ops.len() < 2 {
            return;
        }
        
        // Look for vulnerability patterns
        
        // Pattern 1: Inconsistent masking - using different masks for the same data
        let mut has_inconsistent_masking = false;
        let mut masks = Vec::new();
        
        // Extract potential mask values (often these are PUSH operations before AND)
        for &(pos, opcode) in &bit_ops {
            if opcode == AND && pos > 0 {
                // Look for PUSH operations before AND (simplified approach)
                let mut push_pos = pos;
                while push_pos > 0 && push_pos > pos.saturating_sub(10) {
                    push_pos -= 1;
                    if self.bytecode[push_pos] >= 0x60 && self.bytecode[push_pos] <= 0x7f {
                        // Found a PUSH operation
                        let push_size = (self.bytecode[push_pos] - 0x60 + 1) as usize;
                        if push_pos + push_size < self.bytecode.len() {
                            // Extract the mask value
                            let mask_bytes = &self.bytecode[push_pos+1..push_pos+1+push_size];
                            masks.push(mask_bytes.to_vec());
                        }
                        break;
                    }
                }
            }
        }
        
        // Check for inconsistent masks - we consider it suspicious if there are multiple different masks
        // being used in bit operations, especially if they have similar but not identical patterns
        if masks.len() >= 2 {
            // Compare masks for suspicious patterns
            for i in 0..masks.len() {
                for j in i+1..masks.len() {
                    // Skip comparison if masks are of different lengths
                    if masks[i].len() != masks[j].len() {
                        continue;
                    }
                    
                    // Check if masks are similar but not identical
                    let mut differences = 0;
                    let mut total_bits = 0;
                    
                    for k in 0..masks[i].len() {
                        let byte_i = masks[i][k];
                        let byte_j = masks[j][k];
                        
                        if byte_i != byte_j {
                            // Count differing bits
                            let diff_bits = (byte_i ^ byte_j).count_ones();
                            differences += diff_bits;
                        }
                        
                        total_bits += 8; // 8 bits per byte
                    }
                    
                    // If masks differ by only a few bits, this might indicate a mistake
                    // We use a threshold of 25% different bits
                    if differences > 0 && (differences as f64) / (total_bits as f64) < 0.25 {
                        has_inconsistent_masking = true;
                        break;
                    }
                }
                
                if has_inconsistent_masking {
                    break;
                }
            }
        }
        
        // Pattern 2: Shift followed by incorrect masking
        let mut has_shift_mask_issue = false;
        
        for i in 0..bit_ops.len().saturating_sub(1) {
            let (pos1, op1) = bit_ops[i];
            let (pos2, op2) = bit_ops[i + 1];
            
            // Check for shift followed by AND
            if (op1 == SHL || op1 == SHR || op1 == SAR) && op2 == AND {
                // This is a potential issue if the mask doesn't account for the shift
                // We need to check if the mask is appropriate for the shift
                
                // For a proper implementation, we would track the stack state to verify this
                // For now, we'll use a heuristic: check if the mask value accounts for the shift
                
                // Look for PUSH operations before AND to get the mask value
                if pos2 > 0 {
                    let mut push_pos = pos2;
                    let mut found_mask = false;
                    let mut mask_value = Vec::new();
                    
                    while push_pos > 0 && push_pos > pos2.saturating_sub(10) && !found_mask {
                        push_pos -= 1;
                        if self.bytecode[push_pos] >= 0x60 && self.bytecode[push_pos] <= 0x7f {
                            // Found a PUSH operation
                            let push_size = (self.bytecode[push_pos] - 0x60 + 1) as usize;
                            if push_pos + push_size < self.bytecode.len() {
                                // Extract the mask value
                                mask_value = self.bytecode[push_pos+1..push_pos+1+push_size].to_vec();
                                found_mask = true;
                            }
                        }
                    }
                    
                    // Look for PUSH operations before SHL/SHR/SAR to get the shift amount
                    let mut _shift_amount = 0;
                    let shift_pos = pos1;
                    
                    // Check if the shift amount is a constant (PUSH)
                    if shift_pos > 0 && self.bytecode[shift_pos-1] >= 0x60 && self.bytecode[shift_pos-1] <= 0x7f {
                        // PUSH operation before shift, extract the value
                        let push_size = (self.bytecode[shift_pos-1] - 0x60 + 1) as usize;
                        if shift_pos >= push_size {
                            // Extract the shift amount
                            _shift_amount = self.bytecode[shift_pos+1] as u32;
                        }
                    }
                    
                    // If we found both the mask and shift amount, check if the mask is appropriate
                    if found_mask && pos2 > pos1 && pos2 - pos1 < 5 {
                        // Check if there are any other operations between the shift and AND
                        let mut has_other_ops = false;
                        for j in pos1+1..pos2 {
                            if self.bytecode[j] < 0x60 || self.bytecode[j] > 0x7f {
                                // Found a non-PUSH operation
                                has_other_ops = true;
                                break;
                            }
                        }
                        
                        // If there are no other operations, it's more likely to be a vulnerability
                        if !has_other_ops {
                            has_shift_mask_issue = true;
                        }
                    }
                }
                
                // If we couldn't determine the mask appropriateness, use proximity as a fallback heuristic
                if !has_shift_mask_issue && pos2 > pos1 && pos2 - pos1 < 5 {
                    // Check if there are any other operations between the shift and AND
                    let mut has_other_ops = false;
                    for j in pos1+1..pos2 {
                        if self.bytecode[j] < 0x60 || self.bytecode[j] > 0x7f {
                            // Found a non-PUSH operation
                            has_other_ops = true;
                            break;
                        }
                    }
                    
                    // If there are no other operations, it's more likely to be a vulnerability
                    if !has_other_ops {
                        has_shift_mask_issue = true;
                    }
                }
            }
        }
        
        // Pattern 3: Multiple bit operations without proper validation
        let mut has_complex_bit_sequence = false;
        
        // Instead of just counting operations, look for specific problematic sequences
        for i in 0..bit_ops.len().saturating_sub(2) {
            let (pos1, op1) = bit_ops[i];
            let (pos2, op2) = bit_ops[i + 1];
            let (pos3, op3) = bit_ops[i + 2];
            
            // Check if the operations are close together (within 10 bytes)
            if pos3 > pos1 && pos3 - pos1 < 10 {
                // Check for problematic sequences like:
                // 1. Multiple shifts without proper masking
                let all_shifts = (op1 == SHL || op1 == SHR || op1 == SAR) && 
                                (op2 == SHL || op2 == SHR || op2 == SAR) && 
                                (op3 != AND); // No masking after shifts
                
                // 2. Complex bit manipulation without validation
                let complex_sequence = (op1 == AND || op1 == OR || op1 == XOR) && 
                                      (op2 == AND || op2 == OR || op2 == XOR) && 
                                      (op3 == AND || op3 == OR || op3 == XOR);
                
                // Check if there's any validation between operations
                let mut has_validation = false;
                for j in pos1..pos3 {
                    // Look for comparison operations (EQ, GT, LT, etc.) that might indicate validation
                    if self.bytecode[j] >= 0x10 && self.bytecode[j] <= 0x14 {
                        has_validation = true;
                        break;
                    }
                }
                
                if all_shifts || (complex_sequence && !has_validation) {
                    has_complex_bit_sequence = true;
                    break;
                }
            }
        }
        
        // If any of our patterns are detected, report the vulnerability
        if has_inconsistent_masking || has_shift_mask_issue || has_complex_bit_sequence {
            let mut description = "Potential bitmask vulnerability detected: ".to_string();
            
            if has_inconsistent_masking {
                description.push_str("inconsistent bit masks used; ");
            }
            
            if has_shift_mask_issue {
                description.push_str("shift operation followed by potentially incorrect masking; ");
            }
            
            if has_complex_bit_sequence {
                description.push_str("complex sequence of bit operations without proper validation; ");
            }
            
            // Report the vulnerability at the position of the first bit operation
            if !bit_ops.is_empty() {
                self.vulnerabilities.push(VulnerabilityData {
                    vulnerability_type: VulnerabilityType::BitmaskVulnerability,
                    offset: bit_ops[0].0,
                    description,
                    severity: 3, // Medium severity
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

/// Convert API vulnerability types to analyzer vulnerability types
pub fn convert_vulnerability_types(
    api_vulnerability_types: &[crate::api::VulnerabilityType],
) -> Vec<VulnerabilityType> {
    let mut result = Vec::new();
    for vuln in api_vulnerability_types {
        match vuln {
            crate::api::VulnerabilityType::Reentrancy => {
                result.push(VulnerabilityType::Reentrancy);
            }
            crate::api::VulnerabilityType::IntegerOverflow => {
                result.push(VulnerabilityType::IntegerOverflow);
            }
            crate::api::VulnerabilityType::UnboundedLoop => {
                result.push(VulnerabilityType::UnboundedLoop);
            }
            crate::api::VulnerabilityType::UncheckedCall => {
                result.push(VulnerabilityType::UncheckedCall);
            }
            crate::api::VulnerabilityType::AccessControl => {
                result.push(VulnerabilityType::AccessControl);
            }
            crate::api::VulnerabilityType::SelfDestruct => {
                result.push(VulnerabilityType::SelfDestruct);
            }
            crate::api::VulnerabilityType::OracleManipulation => {
                result.push(VulnerabilityType::OracleManipulation);
            }
            crate::api::VulnerabilityType::MevVulnerability => {
                result.push(VulnerabilityType::MevVulnerability);
            }
            crate::api::VulnerabilityType::FrontRunning => {
                result.push(VulnerabilityType::FrontRunning);
            }
            crate::api::VulnerabilityType::PriceManipulation => {
                result.push(VulnerabilityType::PriceManipulation);
            }
            crate::api::VulnerabilityType::BlockNumberDependence => {
                result.push(VulnerabilityType::BlockNumberDependence);
            }
            crate::api::VulnerabilityType::UninitializedStorage => {
                result.push(VulnerabilityType::UninitializedStorage);
            }
            crate::api::VulnerabilityType::ProxyVulnerability => {
                result.push(VulnerabilityType::ProxyVulnerability);
            }
            crate::api::VulnerabilityType::GasGriefing => {
                result.push(VulnerabilityType::GasGriefing);
            }
            crate::api::VulnerabilityType::WeakRandomness => {
                result.push(VulnerabilityType::WeakRandomness);
            }
            crate::api::VulnerabilityType::GovernanceVulnerability => {
                result.push(VulnerabilityType::GovernanceVulnerability);
            }
            crate::api::VulnerabilityType::BitmaskVulnerability => {
                result.push(VulnerabilityType::BitmaskVulnerability);
            }
            crate::api::VulnerabilityType::PrecisionLoss => {
                result.push(VulnerabilityType::PrecisionLoss);
            }
            crate::api::VulnerabilityType::CentralizedControl => {
                result.push(VulnerabilityType::CentralizedControl);
            }
            crate::api::VulnerabilityType::InsufficientSlippageProtection => {
                result.push(VulnerabilityType::InsufficientSlippageProtection);
            }
            crate::api::VulnerabilityType::TimelockIssue => {
                result.push(VulnerabilityType::TimelockIssue);
            }
            crate::api::VulnerabilityType::UncheckedReturnValue => {
                result.push(VulnerabilityType::UncheckedReturnValue);
            }
            crate::api::VulnerabilityType::CrossContractReentrancy => {
                result.push(VulnerabilityType::CrossContractReentrancy);
            }
            crate::api::VulnerabilityType::Other(x) => {
                result.push(VulnerabilityType::Other(*x));
            }
            _ => {
                result.push(VulnerabilityType::Other(255));
            }
        }
    }
    result
}
