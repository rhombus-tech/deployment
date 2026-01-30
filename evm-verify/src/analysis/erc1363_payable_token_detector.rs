/// ERC-1363 Payable Token Detector
///
/// Detects vulnerabilities in ERC-1363 payable token implementations
/// (tokens with transfer callbacks).

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc1363Vulnerability {
    pub vulnerability_type: Erc1363VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc1363VulnerabilityType {
    CallbackReentrancy,             // Reentrancy via onTransferReceived
    GasGriefing,                    // Callback consumes excessive gas
    CallbackReturnValueIgnored,     // Return value not checked
    UnprotectedCallback,            // No validation of callback contract
    TransferAndCallRaceCondition,   // Race in transferAndCall
    ApproveAndCallExploit,          // approveAndCall manipulation
    ReceiverRejectionIgnored,       // Receiver can reject but not handled
    CallbackDataManipulation,       // Callback data not validated
    DoubleSpendViaCallback,         // Reenter to double-spend
    MaliciousReceiverDOS,           // Receiver always reverts
}

pub struct Erc1363PayableTokenDetector {
    bytecode: Vec<u8>,
}

impl Erc1363PayableTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc1363Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_callback_reentrancy());
        vulnerabilities.extend(self.detect_gas_griefing());
        
        vulnerabilities
    }
    
    fn detect_callback_reentrancy(&self) -> Vec<Erc1363Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut transfers_tokens = false;
            let mut calls_receiver = false;
            let mut has_reentrancy_guard = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0x55 { // SSTORE (balance update)
                    transfers_tokens = true;
                }
                if self.bytecode[j] == 0xF1 { // CALL (callback)
                    calls_receiver = true;
                }
                if self.bytecode[j] == 0x54 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 {
                    has_reentrancy_guard = true;
                }
            }
            
            if transfers_tokens && calls_receiver && !has_reentrancy_guard {
                vulnerabilities.push(Erc1363Vulnerability {
                    vulnerability_type: Erc1363VulnerabilityType::CallbackReentrancy,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "transferAndCall executes callback without reentrancy protection.".to_string(),
                    exploit_scenario: "1. Attacker calls transferAndCall(victim, 100, data)\n\
                                      2. Token updates balances\n\
                                      3. Calls victim.onTransferReceived()\n\
                                      4. Victim is attacker's contract\n\
                                      5. Attacker reenters transferAndCall again\n\
                                      6. Double-spends tokens\n\
                                      7. $500K+ stolen via callback reentrancy".to_string(),
                    recommendation: "Add nonReentrant modifier. Update state before callback. \
                                  Use Checks-Effects-Interactions pattern.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_gas_griefing(&self) -> Vec<Erc1363Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut makes_callback = false;
            let mut limits_gas = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0xF1 { // CALL
                    makes_callback = true;
                }
                if self.bytecode[j] == 0x5A { // GAS
                    limits_gas = true;
                }
            }
            
            if makes_callback && !limits_gas {
                vulnerabilities.push(Erc1363Vulnerability {
                    vulnerability_type: Erc1363VulnerabilityType::GasGriefing,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Callback has no gas limit. Receiver can grief sender with high gas consumption.".to_string(),
                    exploit_scenario: "1. User sends tokens via transferAndCall\n\
                                      2. Receiver callback runs infinite loop\n\
                                      3. User's tx runs out of gas\n\
                                      4. User pays maximum gas but tx reverts\n\
                                      5. $1000+ wasted on gas griefing per tx".to_string(),
                    recommendation: "Limit callback gas to reasonable amount (e.g., 100K gas). \
                                  Use try-catch for callback. Add timeout mechanism.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_callback_reentrancy() {
        let bytecode = vec![
            0x55, // SSTORE
            0xF1, // CALL (no guard)
        ];
        
        let detector = Erc1363PayableTokenDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc1363VulnerabilityType::CallbackReentrancy
        )));
    }
}
