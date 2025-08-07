use crate::bytecode::analyzer::BytecodeAnalyzer;
use ethers::types::{H160, H256, Bytes};
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use log::info;
use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

/// Represents the type of relationship between contracts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractRelation {
    /// Standard external call (CALL)
    Call,
    /// Delegate call (DELEGATECALL)
    DelegateCall,
    /// Static call (STATICCALL)
    StaticCall,
    /// Contract creation (CREATE/CREATE2)
    Create,
}

/// Information about a call between contracts (enhanced version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallInfo {
    /// Type of call opcode
    pub call_type: u8,
    /// Target address of the call
    pub target_address: Option<H256>,
    /// Gas limit for the call
    pub gas_limit: Option<H256>,
    /// Value transferred in the call
    pub value: Option<H256>,
    /// Data offset parameter
    pub data_offset: Option<H256>,
    /// Data size parameter
    pub data_size: Option<H256>,
    /// Return offset parameter
    pub ret_offset: Option<H256>,
    /// Return size parameter
    pub ret_size: Option<H256>,
}

/// Access control pattern types for analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Uses CALLER opcode for access control
    CallerCheck(usize),
    /// Uses ORIGIN opcode for access control (vulnerable)
    OriginCheck(usize),
    /// Uses ADDRESS opcode for self-checks
    SelfCheck(usize),
}

/// Types of protocol-level security findings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolFindingKind {
    /// Cross-contract reentrancy
    CrossContractReentrancy,
    /// Inconsistent access control across contracts
    InconsistentAccessControl,
    /// Privilege escalation across contracts
    PrivilegeEscalation,
    /// Value leakage across contracts
    ValueLeakage,
    /// State inconsistency across contracts
    StateInconsistency,
    /// Circular dependency between contracts
    CircularDependency,
    /// Oracle manipulation
    OracleManipulation,
    /// Flash loan attack vector
    FlashLoanAttackVector,
    /// Upgrade dependency risk
    UpgradeDependencyRisk,
    /// Other findings types
    Other,
}

/// Severity levels for protocol findings
type ProtocolSeverity = SecuritySeverity;

/// A finding that spans multiple contracts in a protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolFinding {
    /// Kind of finding
    pub kind: ProtocolFindingKind,
    /// Severity level
    pub severity: ProtocolSeverity,
    /// Description of the issue
    pub description: String,
    /// Path of contracts involved
    pub call_path: Vec<H160>,
    /// Remediation suggestions
    pub remediation: String,
}

/// Represents a full smart contract protocol with multiple contracts
pub struct ContractProtocol {
    /// Contract bytecodes
    contracts: HashMap<H160, Vec<u8>>,
    /// Contract analyzers
    analyzers: HashMap<H160, Arc<BytecodeAnalyzer>>,
    /// Security findings
    findings: Vec<ProtocolFinding>,
}

impl ContractProtocol {
    /// Create a new empty protocol analysis
    pub fn new() -> Self {
        ContractProtocol {
            contracts: HashMap::new(),
            analyzers: HashMap::new(),
            findings: Vec::new(),
        }
    }

    /// Add a contract to the protocol for analysis
    pub fn add_contract(&mut self, address: H160, bytecode: Vec<u8>) -> Result<()> {
        if self.contracts.contains_key(&address) {
            return Ok(());  // Contract already exists
        }

        // Create an analyzer for this contract
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.clone()));
        let analyzer_arc = Arc::new(analyzer);

        // Add to our collections
        self.contracts.insert(address, bytecode);
        self.analyzers.insert(address, analyzer_arc);

        Ok(())
    }

    /// Build the call graph by analyzing all contracts and their interactions
    pub fn build_call_graph(&mut self) -> Result<()> {
        // In this simplified implementation, we'll just log some information
        // about the contracts without building an actual graph structure
        
        for (address, _analyzer) in &self.analyzers {
            // Just log that we're processing this contract
            info!("Processing contract at address: {:?}", address);
        }
        
        Ok(())
    }

    /// Extract external calls from a contract with advanced stack simulation
    fn extract_external_calls(
        &self,
        analyzer: &BytecodeAnalyzer, 
        source_address: H160,
    ) -> Result<Vec<(H160, CallInfo)>> {
        let bytecode = analyzer.get_bytecode_vec();
        let mut calls = Vec::new();
        let mut stack: Vec<H256> = Vec::new();
        let mut pc = 0;
        
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            match opcode {
                // Stack operations for call target tracking
                0x60..=0x7F => { // PUSH1 to PUSH32
                    let push_size = (opcode - 0x60 + 1) as usize;
                    if pc + push_size < bytecode.len() {
                        let mut value = H256::zero();
                        let start_idx = 32 - push_size;
                        for i in 0..push_size {
                            if pc + 1 + i < bytecode.len() {
                                value.as_bytes_mut()[start_idx + i] = bytecode[pc + 1 + i];
                            }
                        }
                        stack.push(value);
                        pc += push_size + 1;
                    } else {
                        pc += 1;
                    }
                },
                0x80 => { // DUP1
                    if !stack.is_empty() {
                        let top = stack[stack.len() - 1];
                        stack.push(top);
                    }
                    pc += 1;
                },
                0x81..=0x8F => { // DUP2 to DUP16
                    let dup_pos = (opcode - 0x80) as usize;
                    if stack.len() >= dup_pos {
                        let value = stack[stack.len() - dup_pos];
                        stack.push(value);
                    }
                    pc += 1;
                },
                0x90..=0x9F => { // SWAP1 to SWAP16
                    let swap_pos = (opcode - 0x8F) as usize;
                    if stack.len() >= swap_pos {
                        let top_idx = stack.len() - 1;
                        let swap_idx = stack.len() - swap_pos;
                        stack.swap(top_idx, swap_idx);
                    }
                    pc += 1;
                },
                0x50 => { // POP
                    if !stack.is_empty() {
                        stack.pop();
                    }
                    pc += 1;
                },
                // External call opcodes
                0xF1 => { // CALL
                    if stack.len() >= 7 {
                        let target_address = stack[stack.len() - 2]; // address is 2nd from top
                        let gas = stack[stack.len() - 1];
                        let value = stack[stack.len() - 3];
                        
                        let call_info = CallInfo {
                            call_type: 0xF1,
                            target_address: Some(target_address),
                            gas_limit: Some(gas),
                            value: Some(value),
                            data_offset: stack.get(stack.len() - 4).copied(),
                            data_size: stack.get(stack.len() - 5).copied(),
                            ret_offset: stack.get(stack.len() - 6).copied(),
                            ret_size: stack.get(stack.len() - 7).copied(),
                        };
                        
                        // Convert target_address to H160
                        let target_h160 = H160::from_slice(&target_address.as_bytes()[12..32]);
                        calls.push((target_h160, call_info));
                        
                        // Simulate stack after call (removes 7 args, pushes 1 result)
                        for _ in 0..7 {
                            if !stack.is_empty() { stack.pop(); }
                        }
                        stack.push(H256::from_low_u64_be(1)); // Success result
                    }
                    pc += 1;
                },
                0xF2 => { // CALLCODE
                    if stack.len() >= 7 {
                        let target_address = stack[stack.len() - 2];
                        let call_info = CallInfo {
                            call_type: 0xF2,
                            target_address: Some(target_address),
                            gas_limit: stack.get(stack.len() - 1).copied(),
                            value: stack.get(stack.len() - 3).copied(),
                            data_offset: stack.get(stack.len() - 4).copied(),
                            data_size: stack.get(stack.len() - 5).copied(),
                            ret_offset: stack.get(stack.len() - 6).copied(),
                            ret_size: stack.get(stack.len() - 7).copied(),
                        };
                        
                        let target_h160 = H160::from_slice(&target_address.as_bytes()[12..32]);
                        calls.push((target_h160, call_info));
                        
                        for _ in 0..7 { if !stack.is_empty() { stack.pop(); } }
                        stack.push(H256::from_low_u64_be(1));
                    }
                    pc += 1;
                },
                0xF4 => { // DELEGATECALL
                    if stack.len() >= 6 {
                        let target_address = stack[stack.len() - 2];
                        let call_info = CallInfo {
                            call_type: 0xF4,
                            target_address: Some(target_address),
                            gas_limit: stack.get(stack.len() - 1).copied(),
                            value: None, // No value in DELEGATECALL
                            data_offset: stack.get(stack.len() - 3).copied(),
                            data_size: stack.get(stack.len() - 4).copied(),
                            ret_offset: stack.get(stack.len() - 5).copied(),
                            ret_size: stack.get(stack.len() - 6).copied(),
                        };
                        
                        let target_h160 = H160::from_slice(&target_address.as_bytes()[12..32]);
                        calls.push((target_h160, call_info));
                        
                        for _ in 0..6 { if !stack.is_empty() { stack.pop(); } }
                        stack.push(H256::from_low_u64_be(1));
                    }
                    pc += 1;
                },
                0xFA => { // STATICCALL
                    if stack.len() >= 6 {
                        let target_address = stack[stack.len() - 2];
                        let call_info = CallInfo {
                            call_type: 0xFA,
                            target_address: Some(target_address),
                            gas_limit: stack.get(stack.len() - 1).copied(),
                            value: None, // No value in STATICCALL
                            data_offset: stack.get(stack.len() - 3).copied(),
                            data_size: stack.get(stack.len() - 4).copied(),
                            ret_offset: stack.get(stack.len() - 5).copied(),
                            ret_size: stack.get(stack.len() - 6).copied(),
                        };
                        
                        let target_h160 = H160::from_slice(&target_address.as_bytes()[12..32]);
                        calls.push((target_h160, call_info));
                        
                        for _ in 0..6 { if !stack.is_empty() { stack.pop(); } }
                        stack.push(H256::from_low_u64_be(1));
                    }
                    pc += 1;
                },
                _ => {
                    pc += 1;
                }
            }
        }
        
        Ok(calls)
    }
    
    /// Detect cross-contract reentrancy with advanced pattern analysis
    pub fn detect_cross_contract_reentrancy(&mut self) -> Result<()> {
        // Advanced multi-contract reentrancy detection
        for (source_address, source_analyzer) in &self.analyzers {
            // Extract external calls from this contract
            let external_calls = self.extract_external_calls(source_analyzer, *source_address)?;
            
            for (target_address, call_info) in external_calls {
                // Check if target is in our protocol
                if let Some(target_analyzer) = self.analyzers.get(&target_address) {
                    // Analyze reentrancy patterns
                    if self.has_reentrancy_pattern(source_analyzer, target_analyzer, &call_info)? {
                        let call_path = vec![*source_address, target_address];
                        
                        let severity = match call_info.call_type {
                            0xF4 => SecuritySeverity::Critical, // DELEGATECALL is most dangerous
                            0xF1 => SecuritySeverity::High,     // CALL with value
                            _ => SecuritySeverity::Medium,      // STATICCALL, CALLCODE
                        };
                        
                        let finding = ProtocolFinding {
                            kind: ProtocolFindingKind::CrossContractReentrancy,
                            severity,
                            description: format!(
                                "Cross-contract reentrancy vulnerability detected between {:?} and {:?}. \
                                Contract {:?} calls {:?} (opcode 0x{:02X}) without proper reentrancy guards, \
                                allowing potential state manipulation through callback chains.",
                                source_address, target_address, source_address, target_address, call_info.call_type
                            ),
                            call_path,
                            remediation: format!(
                                "1. Implement reentrancy guard modifier on vulnerable functions\n\
                                2. Use checks-effects-interactions pattern\n\
                                3. Consider using ReentrancyGuard from OpenZeppelin\n\
                                4. For DELEGATECALL: Validate target contract thoroughly\n\
                                5. Add mutex locks for cross-contract state changes"
                            ),
                        };
                        
                        self.findings.push(finding);
                    }
                    
                    // Check for circular reentrancy (A->B->A)
                    if self.has_circular_reentrancy(*source_address, target_address)? {
                        let finding = ProtocolFinding {
                            kind: ProtocolFindingKind::CircularDependency,
                            severity: SecuritySeverity::Critical,
                            description: format!(
                                "Circular reentrancy dependency detected: {:?} <-> {:?}. \
                                This creates complex attack vectors through callback chains.",
                                source_address, target_address
                            ),
                            call_path: vec![*source_address, target_address, *source_address],
                            remediation: "Break circular dependencies by introducing intermediate validation layers.".to_string(),
                        };
                        self.findings.push(finding);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Analyze the protocol for cross-contract vulnerabilities
    pub fn analyze(&mut self) -> Result<Vec<ProtocolFinding>> {
        // Clear previous findings
        self.findings.clear();
        
        // Build call graph first
        self.build_call_graph()?;
        
        // Comprehensive vulnerability detection
        self.detect_cross_contract_reentrancy()?;
        self.detect_access_control_inconsistencies()?;
        self.detect_privilege_escalation()?;
        self.detect_value_leakage()?;
        self.detect_state_inconsistency()?;
        
        // Return findings
        Ok(self.findings.clone())
    }
    
    /// Detect privilege escalation vulnerabilities across contracts
    pub fn detect_privilege_escalation(&mut self) -> Result<()> {
        for (source_address, source_analyzer) in &self.analyzers {
            let external_calls = self.extract_external_calls(source_analyzer, *source_address)?;
            
            for (target_address, call_info) in external_calls {
                if let Some(_target_analyzer) = self.analyzers.get(&target_address) {
                    // Check for DELEGATECALL without proper validation
                    if call_info.call_type == 0xF4 { // DELEGATECALL
                        let finding = ProtocolFinding {
                            kind: ProtocolFindingKind::PrivilegeEscalation,
                            severity: SecuritySeverity::Critical,
                            description: format!(
                                "Potential privilege escalation via DELEGATECALL from {:?} to {:?}. \
                                DELEGATECALL executes target code in caller's context, potentially \
                                allowing privilege escalation if target is not properly validated.",
                                source_address, target_address
                            ),
                            call_path: vec![*source_address, target_address],
                            remediation: "1. Validate target contract is trusted implementation\n\
                                2. Use proxy patterns with proper access controls\n\
                                3. Consider using STATICCALL for read-only operations\n\
                                4. Implement whitelist for allowed delegate targets".to_string(),
                        };
                        self.findings.push(finding);
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Detect value leakage vulnerabilities across contracts
    pub fn detect_value_leakage(&mut self) -> Result<()> {
        for (source_address, source_analyzer) in &self.analyzers {
            let external_calls = self.extract_external_calls(source_analyzer, *source_address)?;
            
            for (target_address, call_info) in external_calls {
                if let Some(_target_analyzer) = self.analyzers.get(&target_address) {
                    // Check for calls that transfer value without proper validation
                    if call_info.value.is_some() && call_info.value.unwrap() != H256::zero() {
                        let severity = if call_info.call_type == 0xF1 { // CALL with value
                            SecuritySeverity::High
                        } else {
                            SecuritySeverity::Medium
                        };
                        
                        let finding = ProtocolFinding {
                            kind: ProtocolFindingKind::ValueLeakage,
                            severity,
                            description: format!(
                                "Potential value leakage from {:?} to {:?}. \
                                Contract transfers ETH without proper validation or access controls, \
                                potentially allowing unauthorized fund drainage.",
                                source_address, target_address
                            ),
                            call_path: vec![*source_address, target_address],
                            remediation: "1. Implement proper access controls for value transfers\n\
                                2. Add balance checks before and after transfers\n\
                                3. Use pull payment pattern instead of push payments\n\
                                4. Implement withdrawal limits and timelock mechanisms".to_string(),
                        };
                        self.findings.push(finding);
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Detect state inconsistency vulnerabilities across contracts
    pub fn detect_state_inconsistency(&mut self) -> Result<()> {
        // Check for contracts that share state but lack synchronization
        let mut shared_state_contracts = Vec::new();
        
        for (address, _analyzer) in &self.analyzers {
            shared_state_contracts.push(*address);
        }
        
        // If we have multiple contracts, check for potential state inconsistency
        if shared_state_contracts.len() > 1 {
            for i in 0..shared_state_contracts.len() {
                for j in (i + 1)..shared_state_contracts.len() {
                    let addr_a = shared_state_contracts[i];
                    let addr_b = shared_state_contracts[j];
                    
                    // Check if contracts can call each other (potential shared state)
                    if self.can_call_contract(addr_a, addr_b)? || self.can_call_contract(addr_b, addr_a)? {
                        let finding = ProtocolFinding {
                            kind: ProtocolFindingKind::StateInconsistency,
                            severity: SecuritySeverity::Medium,
                            description: format!(
                                "Potential state inconsistency between {:?} and {:?}. \
                                Contracts that share state or interact frequently should \
                                implement proper synchronization mechanisms.",
                                addr_a, addr_b
                            ),
                            call_path: vec![addr_a, addr_b],
                            remediation: "1. Implement state synchronization mechanisms\n\
                                2. Use atomic operations for cross-contract state changes\n\
                                3. Add state validation checks after external calls\n\
                                4. Consider using commit-reveal patterns for sensitive state".to_string(),
                        };
                        self.findings.push(finding);
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Find shortest call path between two contracts using Dijkstra's algorithm
    pub fn find_call_path(&self, from: H160, to: H160) -> Option<Vec<H160>> {
        use std::collections::{HashMap, VecDeque};
        
        if from == to {
            return Some(vec![from]);
        }
        
        let mut queue = VecDeque::new();
        let mut visited = HashMap::new();
        let mut parent = HashMap::new();
        
        queue.push_back(from);
        visited.insert(from, true);
        
        while let Some(current) = queue.pop_front() {
            if let Some(analyzer) = self.analyzers.get(&current) {
                let external_calls = self.extract_external_calls(analyzer, current).unwrap_or_default();
                
                for (target_address, _) in external_calls {
                    if target_address == to {
                        // Found target, reconstruct path
                        let mut path = vec![target_address];
                        let mut node = current;
                        path.push(node);
                        
                        while let Some(&prev) = parent.get(&node) {
                            path.push(prev);
                            node = prev;
                        }
                        
                        path.reverse();
                        return Some(path);
                    }
                    
                    if !visited.contains_key(&target_address) {
                        visited.insert(target_address, true);
                        parent.insert(target_address, current);
                        queue.push_back(target_address);
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if two contracts have reentrancy vulnerability pattern
    fn has_reentrancy_pattern(
        &self,
        source_analyzer: &BytecodeAnalyzer,
        target_analyzer: &BytecodeAnalyzer,
        call_info: &CallInfo,
    ) -> Result<bool> {
        // Advanced reentrancy pattern detection
        
        // 1. Check if source has state changes after external calls
        let source_has_state_changes_after_calls = self.has_state_changes_after_calls(source_analyzer)?;
        
        // 2. Check if target can callback to source
        let target_can_callback = self.can_callback_to_source(target_analyzer)?;
        
        // 3. Check if call transfers value (higher risk)
        let transfers_value = call_info.value.is_some() && 
            call_info.value.unwrap() != H256::zero();
        
        // 4. Check for delegate call patterns (critical risk)
        let is_delegatecall = call_info.call_type == 0xF4;
        
        // 5. Check for lack of reentrancy guards
        let lacks_reentrancy_guard = !self.has_reentrancy_guard(source_analyzer)?;
        
        // Pattern is vulnerable if multiple conditions are met
        let is_vulnerable = source_has_state_changes_after_calls && 
            (target_can_callback || is_delegatecall || transfers_value) &&
            lacks_reentrancy_guard;
        
        Ok(is_vulnerable)
    }
    
    /// Check if contract has state changes after external calls
    fn has_state_changes_after_calls(&self, analyzer: &BytecodeAnalyzer) -> Result<bool> {
        let bytecode = analyzer.get_bytecode_vec();
        let mut pc = 0;
        let mut found_call = false;
        let mut call_positions = Vec::new();
        
        // First pass: find all external call positions
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            if matches!(opcode, 0xF1 | 0xF2 | 0xF4 | 0xFA) { // CALL, CALLCODE, DELEGATECALL, STATICCALL
                call_positions.push(pc);
                found_call = true;
            }
            pc += 1;
        }
        
        if !found_call {
            return Ok(false);
        }
        
        // Second pass: check for SSTORE after any call
        pc = 0;
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            if opcode == 0x55 { // SSTORE
                // Check if this SSTORE comes after any call
                if call_positions.iter().any(|&call_pos| call_pos < pc) {
                    return Ok(true);
                }
            }
            pc += 1;
        }
        
        Ok(false)
    }
    
    /// Check if contract can make callbacks (has external calls)
    fn can_callback_to_source(&self, analyzer: &BytecodeAnalyzer) -> Result<bool> {
        let bytecode = analyzer.get_bytecode_vec();
        let mut pc = 0;
        
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            if matches!(opcode, 0xF1 | 0xF2 | 0xF4 | 0xFA) { // External call opcodes
                return Ok(true);
            }
            pc += 1;
        }
        
        Ok(false)
    }
    
    /// Check if contract has reentrancy guard pattern
    fn has_reentrancy_guard(&self, analyzer: &BytecodeAnalyzer) -> Result<bool> {
        let bytecode = analyzer.get_bytecode_vec();
        let mut pc = 0;
        let mut has_guard_check = false;
        let mut has_guard_set = false;
        
        // Look for common reentrancy guard patterns:
        // 1. SLOAD followed by comparison (checking guard status)
        // 2. SSTORE to set/unset guard
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            match opcode {
                0x54 => { // SLOAD - reading guard status
                    // Check if followed by comparison
                    if pc + 1 < bytecode.len() {
                        let next_op = bytecode[pc + 1];
                        if matches!(next_op, 0x10 | 0x11 | 0x12 | 0x13 | 0x14) { // LT, GT, SLT, SGT, EQ
                            has_guard_check = true;
                        }
                    }
                },
                0x55 => { // SSTORE - setting guard status
                    has_guard_set = true;
                },
                _ => {}
            }
            pc += 1;
        }
        
        // Heuristic: likely has reentrancy guard if both check and set are present
        Ok(has_guard_check && has_guard_set)
    }
    
    /// Check for circular reentrancy between two contracts
    fn has_circular_reentrancy(&self, addr_a: H160, addr_b: H160) -> Result<bool> {
        // Check if A can call B AND B can call A
        let a_can_call_b = self.can_call_contract(addr_a, addr_b)?;
        let b_can_call_a = self.can_call_contract(addr_b, addr_a)?;
        
        Ok(a_can_call_b && b_can_call_a)
    }
    
    /// Check if contract A can call contract B
    fn can_call_contract(&self, from: H160, to: H160) -> Result<bool> {
        if let Some(analyzer) = self.analyzers.get(&from) {
            let external_calls = self.extract_external_calls(analyzer, from)?;
            return Ok(external_calls.iter().any(|(target, _)| *target == to));
        }
        Ok(false)
    }
    
    /// Detect inconsistent access control across contracts
    pub fn detect_access_control_inconsistencies(&mut self) -> Result<()> {
        use std::collections::HashMap;
        
        let mut access_patterns: HashMap<H160, Vec<AccessPattern>> = HashMap::new();
        
        // Analyze access control patterns in each contract
        for (address, analyzer) in &self.analyzers {
            let patterns = self.extract_access_patterns(analyzer)?;
            access_patterns.insert(*address, patterns);
        }
        
        // Compare patterns across contracts for inconsistencies
        let addresses: Vec<H160> = access_patterns.keys().cloned().collect();
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                let addr_a = addresses[i];
                let addr_b = addresses[j];
                
                if self.has_access_control_inconsistency(
                    &access_patterns[&addr_a],
                    &access_patterns[&addr_b],
                )? {
                    let finding = ProtocolFinding {
                        kind: ProtocolFindingKind::InconsistentAccessControl,
                        severity: SecuritySeverity::High,
                        description: format!(
                            "Inconsistent access control patterns detected between {:?} and {:?}. \
                            This could allow privilege escalation or unauthorized access.",
                            addr_a, addr_b
                        ),
                        call_path: vec![addr_a, addr_b],
                        remediation: "Standardize access control patterns across all protocol contracts.".to_string(),
                    };
                    self.findings.push(finding);
                }
            }
        }
        
        Ok(())
    }
    
    /// Extract access control patterns from contract bytecode
    fn extract_access_patterns(&self, analyzer: &BytecodeAnalyzer) -> Result<Vec<AccessPattern>> {
        let mut patterns = Vec::new();
        let bytecode = analyzer.get_bytecode_vec();
        let mut pc = 0;
        
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            match opcode {
                0x33 => { // CALLER - access control check
                    patterns.push(AccessPattern::CallerCheck(pc));
                },
                0x32 => { // ORIGIN - tx.origin check (often vulnerable)
                    patterns.push(AccessPattern::OriginCheck(pc));
                },
                0x30 => { // ADDRESS - address(this) check
                    patterns.push(AccessPattern::SelfCheck(pc));
                },
                _ => {}
            }
            pc += 1;
        }
        
        Ok(patterns)
    }
    
    /// Check for access control inconsistencies between two pattern sets
    fn has_access_control_inconsistency(
        &self,
        patterns_a: &[AccessPattern],
        patterns_b: &[AccessPattern],
    ) -> Result<bool> {
        // Different heuristics for inconsistency detection
        
        // 1. One uses CALLER, other uses ORIGIN (security issue)
        let a_uses_caller = patterns_a.iter().any(|p| matches!(p, AccessPattern::CallerCheck(_)));
        let b_uses_origin = patterns_b.iter().any(|p| matches!(p, AccessPattern::OriginCheck(_)));
        
        let a_uses_origin = patterns_a.iter().any(|p| matches!(p, AccessPattern::OriginCheck(_)));
        let b_uses_caller = patterns_b.iter().any(|p| matches!(p, AccessPattern::CallerCheck(_)));
        
        if (a_uses_caller && b_uses_origin) || (a_uses_origin && b_uses_caller) {
            return Ok(true);
        }
        
        // 2. Significant difference in number of access checks
        let a_check_count = patterns_a.len();
        let b_check_count = patterns_b.len();
        
        if a_check_count == 0 && b_check_count > 2 {
            return Ok(true); // One has no access control, other has multiple
        }
        
        if b_check_count == 0 && a_check_count > 2 {
            return Ok(true);
        }
        
        Ok(false)
    }
}

/// Module tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_analysis_empty() {
        let protocol = ContractProtocol::new();
        assert_eq!(protocol.contracts.len(), 0);
    }
}
