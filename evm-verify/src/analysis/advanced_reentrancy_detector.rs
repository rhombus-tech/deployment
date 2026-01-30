/// Advanced Reentrancy Detector with False Positive Reduction
/// Improvements:
/// 1. Recognizes common protection patterns (EVC, ReentrancyGuard, CEI)
/// 2. Context-aware severity scoring
/// 3. Known-safe pattern whitelisting
/// 4. Cross-function analysis
/// 5. Confidence calibration based on protection mechanisms

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedReentrancyVulnerability {
    pub pc: usize,
    pub severity: SecuritySeverity,
    pub call_opcode: u8,
    pub state_changes_after: Vec<usize>,
    pub description: String,
    pub confidence: f32,
    pub protection_mechanisms: Vec<ProtectionMechanism>,
    pub is_likely_false_positive: bool,
    pub safe_pattern_detected: Option<String>,
    pub has_access_control: bool,
    pub access_control_type: Option<String>,
    pub has_reentrancy_guard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectionMechanism {
    ReentrancyGuard,           // OpenZeppelin ReentrancyGuard
    ChecksEffectsInteractions, // CEI pattern
    EVCDeferredChecks,         // Euler V2 EVC pattern
    StateMutex,                // Custom mutex
    ReadOnly,                  // View/pure functions
    PullPayment,               // Pull over push
}

pub struct AdvancedReentrancyDetector {
    bytecode: Vec<u8>,
    known_safe_patterns: HashSet<Vec<u8>>,
}

impl AdvancedReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut known_safe_patterns = HashSet::new();
        
        // Add known safe patterns
        // OpenZeppelin ReentrancyGuard storage slot pattern
        known_safe_patterns.insert(vec![
            0x60, 0x02, // PUSH1 2 (NOT_ENTERED constant)
            0x54,       // SLOAD
            0x14,       // EQ
            0x60, 0x00, // PUSH1 0
            0x35,       // CALLDATALOAD
            0x14,       // EQ (checking _status == _NOT_ENTERED)
        ]);
        
        // EVC deferred checks pattern (Euler V2)
        known_safe_patterns.insert(vec![
            0x73, // PUSH20 (EVC address)
            // followed by STATICCALL to EVC
            0xFA, // STATICCALL
        ]);
        
        Self {
            bytecode,
            known_safe_patterns,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AdvancedReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let external_calls = self.find_external_calls();
        
        for call_info in external_calls {
            let state_changes = self.find_state_changes_after(call_info.pc);
            
            if state_changes.is_empty() {
                continue; // No state changes after = safe
            }
            
            // Analyze protection mechanisms
            let protections = self.detect_protection_mechanisms(call_info.pc);
            
            // Check for known safe patterns
            let safe_pattern = self.matches_known_safe_pattern(call_info.pc);
            
            // Calculate confidence based on protections
            let (confidence, is_likely_false_positive) = 
                self.calculate_confidence(&protections, &safe_pattern, &call_info, &state_changes);
            
            // Adjust severity based on protections
            let severity = self.calculate_severity(&protections, &call_info, &state_changes);
            
            // Only report if confidence is high enough and not clearly safe
            if confidence > 0.3 && !is_likely_false_positive {
                let has_reentrancy_guard = protections.contains(&ProtectionMechanism::ReentrancyGuard);
                
                vulnerabilities.push(AdvancedReentrancyVulnerability {
                    pc: call_info.pc,
                    severity,
                    call_opcode: call_info.opcode,
                    state_changes_after: state_changes.clone(),
                    description: self.generate_description(&call_info, &protections, &safe_pattern, confidence),
                    confidence,
                    protection_mechanisms: protections.clone(),
                    is_likely_false_positive,
                    safe_pattern_detected: safe_pattern.clone(),
                    has_access_control: false,  // Advanced detector doesn't check this yet
                    access_control_type: None,
                    has_reentrancy_guard,
                });
            }
        }
        
        vulnerabilities
    }

    fn detect_protection_mechanisms(&self, call_pc: usize) -> Vec<ProtectionMechanism> {
        let mut protections = Vec::new();
        
        // Check for ReentrancyGuard pattern (OpenZeppelin)
        if self.has_reentrancy_guard_pattern() {
            protections.push(ProtectionMechanism::ReentrancyGuard);
        }
        
        // Check for EVC deferred checks pattern (Euler V2)
        if self.has_evc_deferred_checks(call_pc) {
            protections.push(ProtectionMechanism::EVCDeferredChecks);
        }
        
        // Check for Checks-Effects-Interactions pattern
        if self.follows_cei_pattern(call_pc) {
            protections.push(ProtectionMechanism::ChecksEffectsInteractions);
        }
        
        // Check for state mutex pattern
        if self.has_state_mutex(call_pc) {
            protections.push(ProtectionMechanism::StateMutex);
        }
        
        // Check if it's a read-only call (STATICCALL)
        if call_pc < self.bytecode.len() && self.bytecode[call_pc] == 0xFA {
            protections.push(ProtectionMechanism::ReadOnly);
        }
        
        protections
    }

    fn has_evc_deferred_checks(&self, call_pc: usize) -> bool {
        // Look for EVC pattern:
        // 1. Call to EVC contract
        // 2. Followed by requireChecksDeferred or similar
        
        // Check if there's a STATICCALL to known EVC address within 500 bytes
        let search_window = call_pc.saturating_sub(500)..call_pc.min(self.bytecode.len());
        
        for i in search_window {
            if i + 21 < self.bytecode.len() {
                // Look for PUSH20 (EVC address) followed by STATICCALL
                if self.bytecode[i] == 0x73 && // PUSH20
                   self.bytecode.get(i + 21) == Some(&0xFA) { // STATICCALL
                    return true;
                }
            }
        }
        
        false
    }

    fn has_reentrancy_guard_pattern(&self) -> bool {
        // OpenZeppelin ReentrancyGuard pattern:
        // _status storage slot check
        
        let pattern_variants = [
            // Pattern 1: Check _status != _ENTERED
            vec![0x54, 0x14, 0x15, 0x57], // SLOAD, EQ, ISZERO, JUMPI
            // Pattern 2: _status == _NOT_ENTERED
            vec![0x54, 0x60, 0x02, 0x14], // SLOAD, PUSH1 2, EQ
            // Pattern 3: require(_status != _ENTERED)
            vec![0x54, 0x60, 0x01, 0x14, 0x15], // SLOAD, PUSH1 1, EQ, ISZERO
        ];
        
        for pattern in &pattern_variants {
            if self.bytecode.windows(pattern.len()).any(|w| w == &pattern[..]) {
                return true;
            }
        }
        
        false
    }

    fn follows_cei_pattern(&self, call_pc: usize) -> bool {
        // Checks-Effects-Interactions: All SSTORE should be BEFORE the CALL
        
        // Look backwards for SSTORE opcodes
        let lookback_start = call_pc.saturating_sub(200);
        let has_sstore_before = self.bytecode[lookback_start..call_pc]
            .iter()
            .any(|&op| op == 0x55); // SSTORE
        
        // Look forward for SSTORE opcodes (fewer than before = good)
        let lookforward_end = (call_pc + 200).min(self.bytecode.len());
        let sstore_count_after = self.bytecode[call_pc..lookforward_end]
            .iter()
            .filter(|&&op| op == 0x55)
            .count();
        
        // If most state changes are BEFORE the call, it follows CEI
        has_sstore_before && sstore_count_after <= 2
    }

    fn has_state_mutex(&self, call_pc: usize) -> bool {
        // Look for custom mutex pattern:
        // locked = true; ... call; locked = false;
        
        let search_before = call_pc.saturating_sub(100)..call_pc;
        let search_after = call_pc..(call_pc + 100).min(self.bytecode.len());
        
        // Look for SSTORE before and after call
        let has_lock = self.bytecode[search_before.clone()]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] == 0x01); // PUSH1 1 (true)
        
        let has_unlock = self.bytecode[search_after]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] == 0x00); // PUSH1 0 (false)
        
        has_lock && has_unlock
    }

    fn matches_known_safe_pattern(&self, call_pc: usize) -> Option<String> {
        // Check if this matches any known-safe patterns
        
        let search_window = call_pc.saturating_sub(50)..call_pc.min(self.bytecode.len());
        
        for pattern in &self.known_safe_patterns {
            if search_window.len() >= pattern.len() {
                if self.bytecode[search_window.clone()]
                    .windows(pattern.len())
                    .any(|w| w == &pattern[..]) {
                    
                    // Identify which safe pattern
                    if pattern.contains(&0xFA) {
                        return Some("Euler V2 EVC Deferred Checks".to_string());
                    } else if pattern.contains(&0x60) && pattern.contains(&0x02) {
                        return Some("OpenZeppelin ReentrancyGuard".to_string());
                    }
                }
            }
        }
        
        None
    }

    fn calculate_confidence(
        &self,
        protections: &[ProtectionMechanism],
        safe_pattern: &Option<String>,
        call_info: &CallInfo,
        state_changes: &[usize],
    ) -> (f32, bool) {
        let mut confidence = 0.95; // Start with high confidence
        let mut is_false_positive = false;
        
        // Reduce confidence for each protection mechanism
        for protection in protections {
            match protection {
                ProtectionMechanism::ReentrancyGuard => {
                    confidence *= 0.2; // 80% reduction - very likely safe
                    is_false_positive = true;
                }
                ProtectionMechanism::EVCDeferredChecks => {
                    confidence *= 0.1; // 90% reduction - Euler V2 pattern
                    is_false_positive = true;
                }
                ProtectionMechanism::ChecksEffectsInteractions => {
                    confidence *= 0.4; // 60% reduction - good pattern
                }
                ProtectionMechanism::StateMutex => {
                    confidence *= 0.3; // 70% reduction
                }
                ProtectionMechanism::ReadOnly => {
                    confidence *= 0.05; // 95% reduction - STATICCALL can't modify state
                    is_false_positive = true;
                }
                ProtectionMechanism::PullPayment => {
                    confidence *= 0.5; // 50% reduction
                }
            }
        }
        
        // Known safe patterns = very likely false positive
        if safe_pattern.is_some() {
            confidence *= 0.1;
            is_false_positive = true;
        }
        
        // Few state changes after = less risky
        if state_changes.len() == 1 {
            confidence *= 0.7; // 30% reduction
        }
        
        // DELEGATECALL is always risky
        if call_info.is_delegatecall {
            confidence = f32::max(confidence, 0.7); // At least 70% confidence
        }
        
        (confidence, is_false_positive)
    }

    fn calculate_severity(
        &self,
        protections: &[ProtectionMechanism],
        call_info: &CallInfo,
        state_changes: &[usize],
    ) -> SecuritySeverity {
        // If protected, downgrade severity
        if protections.contains(&ProtectionMechanism::ReentrancyGuard) ||
           protections.contains(&ProtectionMechanism::EVCDeferredChecks) {
            return SecuritySeverity::Low; // Protected
        }
        
        // DELEGATECALL is critical
        if call_info.is_delegatecall {
            return SecuritySeverity::Critical;
        }
        
        // Many state changes = higher severity
        if state_changes.len() > 5 {
            SecuritySeverity::High
        } else if state_changes.len() > 2 {
            SecuritySeverity::Medium
        } else {
            SecuritySeverity::Low
        }
    }

    fn generate_description(
        &self,
        call_info: &CallInfo,
        protections: &[ProtectionMechanism],
        safe_pattern: &Option<String>,
        confidence: f32,
    ) -> String {
        let mut desc = format!(
            "External call at PC {} with state changes after. ",
            call_info.pc
        );
        
        if let Some(pattern) = safe_pattern {
            desc.push_str(&format!("✅ Protected by: {}. ", pattern));
        }
        
        if !protections.is_empty() {
            desc.push_str("Protection mechanisms detected: ");
            for p in protections {
                desc.push_str(&format!("{:?}, ", p));
            }
        } else {
            desc.push_str("⚠️ No protection mechanisms detected. ");
        }
        
        desc.push_str(&format!("Confidence: {:.0}%", confidence * 100.0));
        
        desc
    }

    fn find_external_calls(&self) -> Vec<CallInfo> {
        let mut calls = Vec::new();
        let mut pc = 0;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            match opcode {
                0xF1 => calls.push(CallInfo { pc, opcode: 0xF1, is_delegatecall: false, transfers_value: true }),
                0xF2 => calls.push(CallInfo { pc, opcode: 0xF2, is_delegatecall: false, transfers_value: true }),
                0xF4 => calls.push(CallInfo { pc, opcode: 0xF4, is_delegatecall: true, transfers_value: false }),
                0xFA => calls.push(CallInfo { pc, opcode: 0xFA, is_delegatecall: false, transfers_value: false }),
                0x60..=0x7F => {
                    // PUSH1-PUSH32: skip the data bytes to avoid false positives
                    // Data bytes inside PUSH instructions are not executable opcodes
                    let push_size = (opcode - 0x5F) as usize;
                    pc += push_size;
                }
                _ => {}
            }
            
            pc += 1;
        }
        
        calls
    }

    fn find_state_changes_after(&self, call_pc: usize) -> Vec<usize> {
        let mut changes = Vec::new();
        let search_end = (call_pc + 500).min(self.bytecode.len());
        let mut i = call_pc + 1;
        
        while i < search_end {
            let opcode = self.bytecode[i];
            
            if opcode == 0x55 { // SSTORE
                changes.push(i);
            }
            
            // Stop at next external call or return
            if matches!(opcode, 0xF1 | 0xF2 | 0xF3 | 0xF4 | 0xFA | 0xF0) {
                break;
            }
            
            // Skip PUSH data bytes to avoid false positives
            if (0x60..=0x7F).contains(&opcode) {
                let push_size = (opcode - 0x5F) as usize;
                i += push_size;
            }
            
            i += 1;
        }
        
        changes
    }
}

#[derive(Debug, Clone)]
struct CallInfo {
    pc: usize,
    opcode: u8,
    is_delegatecall: bool,
    transfers_value: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognizes_reentrancy_guard() {
        let bytecode = vec![
            0x54, // SLOAD (_status)
            0x60, 0x02, // PUSH1 2 (_NOT_ENTERED)
            0x14, // EQ
            0x15, // ISZERO
            0x57, // JUMPI (revert if entered)
            0xF1, // CALL
            0x55, // SSTORE (state change after)
        ];
        
        let detector = AdvancedReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should detect protection and mark as false positive
        assert!(vulns.is_empty() || vulns[0].is_likely_false_positive);
    }

    #[test]
    fn test_unprotected_reentrancy() {
        let bytecode = vec![
            0xF1, // CALL (no guard)
            0x55, // SSTORE (state change after)
        ];
        
        let detector = AdvancedReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should detect as real vulnerability
        assert!(!vulns.is_empty());
        assert!(!vulns[0].is_likely_false_positive);
        assert!(vulns[0].confidence > 0.8);
    }
}
