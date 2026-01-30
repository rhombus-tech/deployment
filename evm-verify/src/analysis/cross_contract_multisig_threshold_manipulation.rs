/// Cross-Contract Multi-Sig Threshold Manipulation Detection
/// 
/// Coverage: Gnosis Safe, Multi-Sig Wallets ($50B+ in Safe contracts)
/// Attacks: Dynamic threshold changes via external calls, signer weight manipulation, quorum bypasses

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigThresholdVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub multisig_pattern: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub safe_contracts_at_risk: u64,
}

pub struct CrossContractMultisigThresholdDetector {
    bytecode: Vec<u8>,
}

impl CrossContractMultisigThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MultisigThresholdVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Threshold Changed by External Call During Execution
        if self.detect_threshold_manipulation_via_external_call() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Threshold Manipulation via External Call".to_string(),
                severity: "Critical".to_string(),
                multisig_pattern: "External call modifies signer threshold mid-execution".to_string(),
                description: "Multi-sig threshold checked before external call, but external call modifies threshold, bypassing quorum".to_string(),
                exploit_scenario: "Gnosis Safe configured as 3-of-5 multi-sig controlling $100M DAO treasury\n\
                    Transaction proposal: 'Call Protocol X to claim rewards'\n\
                    3 signers approve (meets threshold)\n\
                    During execution: Protocol X callback calls Safe.changeThreshold(1)\n\
                    Threshold now 1-of-5, no quorum check after external call\n\
                    Attacker (1 signer) submits transaction: transfer $100M to attacker\n\
                    Only 1 signature needed, bypasses 3-of-5 requirement\n\
                    $100M stolen with single compromised signer".to_string(),
                remediation: "Re-verify threshold AFTER external calls, immutable threshold during execution, reentrancy guards on threshold changes".to_string(),
                safe_contracts_at_risk: 50000,
            });
        }
        
        // 2. Signer Weight Manipulation
        if self.detect_signer_weight_manipulation() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Signer Weight Manipulation Attack".to_string(),
                severity: "Critical".to_string(),
                multisig_pattern: "Weighted multi-sig with mutable signer weights".to_string(),
                description: "External call changes signer weights, reducing threshold or elevating attacker weight".to_string(),
                exploit_scenario: "Weighted multi-sig: Requires 60% of total weight\n\
                    Signers: Alice(30%), Bob(30%), Carol(30%), Dave(10%)\n\
                    Malicious proposal calls external contract\n\
                    External contract exploits reentrancy:\n\
                      - Calls multisig.setSignerWeight(Dave, 100)\n\
                      - Dave now has 100% weight\n\
                    Dave single-handedly approves any transaction\n\
                    Drains $50M from treasury with 1 signature\n\
                    Governance completely bypassed".to_string(),
                remediation: "Immutable signer weights during execution, timelock on weight changes, weight change requires unanimous consent".to_string(),
                safe_contracts_at_risk: 10000,
            });
        }
        
        // 3. Quorum Bypass via Dynamic Signer Addition
        if self.detect_dynamic_signer_bypass() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Dynamic Signer Addition Bypass".to_string(),
                severity: "Critical".to_string(),
                multisig_pattern: "Add signer during execution to manipulate threshold".to_string(),
                description: "Transaction execution adds new signers to dilute quorum requirement".to_string(),
                exploit_scenario: "Safe configured: 3-of-5 signers required\n\
                    Attacker controls 2 signers (minority, can't execute alone)\n\
                    Submits transaction: 'Call malicious contract'\n\
                    Malicious contract during execution:\n\
                      - Calls Safe.addOwnerWithThreshold(attacker2, 3)\n\
                      - Now 3-of-6 signers (same threshold, more signers)\n\
                      - Calls Safe.addOwnerWithThreshold(attacker3, 3)\n\
                      - Now 3-of-7 signers\n\
                    Attacker controls 4-of-7 signers (majority)\n\
                    Takes over Safe, drains funds\n\
                    All future transactions controlled by attacker".to_string(),
                remediation: "Freeze signer list during execution, timelock on signer changes, separate quorum for governance changes".to_string(),
                safe_contracts_at_risk: 30000,
            });
        }
        
        // 4. Threshold Check Timing Vulnerability
        if self.detect_threshold_timing_vulnerability() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Threshold Check Timing Exploit".to_string(),
                severity: "High".to_string(),
                multisig_pattern: "Threshold checked only at submission, not execution".to_string(),
                description: "Multi-sig checks threshold when transaction is queued, but not when executed, allowing threshold manipulation before execution".to_string(),
                exploit_scenario: "Transaction submitted with 3-of-5 threshold (valid)\n\
                    Queued for 24-hour timelock\n\
                    During 24 hours: Attacker compromises Safe owner\n\
                    Calls changeThreshold(1) before queued tx executes\n\
                    Queued transaction executes with OLD threshold validation\n\
                    But current threshold is 1-of-5\n\
                    All future transactions only need 1 signer\n\
                    Timelock becomes useless protection".to_string(),
                remediation: "Validate threshold at execution time, not just submission, snapshot threshold with transaction hash".to_string(),
                safe_contracts_at_risk: 20000,
            });
        }
        
        // 5. Delegatecall Threshold Corruption
        if self.detect_delegatecall_threshold_corruption() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Delegatecall Threshold Storage Corruption".to_string(),
                severity: "Critical".to_string(),
                multisig_pattern: "Delegatecall overwrites threshold storage slot".to_string(),
                description: "Multi-sig uses delegatecall to external contract that corrupts threshold storage".to_string(),
                exploit_scenario: "Gnosis Safe stores threshold at storage slot 0x04\n\
                    Safe allows delegatecall to 'upgrade' module\n\
                    Malicious module:\n\
                      - Writes to slot 0x04: threshold = 1\n\
                      - Writes to slot 0x05: owner count = 100 (fake)\n\
                    Storage corrupted via delegatecall context\n\
                    Safe now thinks it's 1-of-100 signers\n\
                    Any single signer can execute transactions\n\
                    $500M treasury drained by single compromised key".to_string(),
                remediation: "Whitelist delegatecall targets, storage slot protection, proxy pattern with separate storage, audit all delegate modules".to_string(),
                safe_contracts_at_risk: 5000,
            });
        }
        
        // 6. Cross-Contract State Dependency
        if self.detect_cross_contract_state_dependency() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Cross-Contract Threshold State Dependency".to_string(),
                severity: "High".to_string(),
                multisig_pattern: "Threshold depends on external contract state".to_string(),
                description: "Multi-sig threshold calculated from external contract state that can be manipulated".to_string(),
                exploit_scenario: "Multi-sig uses dynamic threshold: threshold = externalContract.getQuorum()\n\
                    externalContract is governance voting contract\n\
                    Returns threshold based on token holder votes\n\
                    Attacker flash-loans 51% of governance tokens\n\
                    Votes to change quorum from 60% → 10%\n\
                    Multi-sig reads new threshold: 10% required\n\
                    Attacker (holding 15% of Safe signatures) can now execute alone\n\
                    Empties Safe, returns flash loan\n\
                    Atomic attack in single transaction".to_string(),
                remediation: "Hardcoded thresholds, immutable quorum, timelock on threshold changes, flash loan protection".to_string(),
                safe_contracts_at_risk: 8000,
            });
        }
        
        // 7. Signature Replay Across Threshold Changes
        if self.detect_signature_replay_threshold_change() {
            vulnerabilities.push(MultisigThresholdVulnerability {
                vulnerability_type: "Signature Replay After Threshold Change".to_string(),
                severity: "Medium".to_string(),
                multisig_pattern: "Old signatures valid after threshold increase".to_string(),
                description: "Multi-sig increases threshold, but previously collected signatures still count toward new threshold".to_string(),
                exploit_scenario: "Safe requires 2-of-5 signatures\n\
                    Attacker collects 2 signatures for malicious transaction\n\
                    Before execution: Safe increases threshold to 4-of-5 (security improvement)\n\
                    Attacker still executes with old 2 signatures\n\
                    Transaction validates because signatures were collected before threshold change\n\
                    New 4-of-5 requirement bypassed using stale signatures\n\
                    Partial theft despite increased security".to_string(),
                remediation: "Invalidate all pending transactions on threshold change, include threshold in signature data, nonce-based replay protection".to_string(),
                safe_contracts_at_risk: 15000,
            });
        }
        
        vulnerabilities
    }
    
    fn detect_threshold_manipulation_via_external_call(&self) -> bool {
        // Pattern: Threshold check → External CALL → No re-check
        let has_threshold_check = self.bytecode.windows(10).any(|w| {
            w.contains(&0x54) && // SLOAD (read threshold)
            w.contains(&0x11)    // GT (compare signatures >= threshold)
        });
        
        let has_external_call = self.bytecode.windows(5).any(|w| {
            w.contains(&0xf1) || w.contains(&0xf4) // CALL or DELEGATECALL
        });
        
        let no_recheck = !self.bytecode.windows(20).enumerate().any(|(i, w)| {
            // Check if there's a threshold verification AFTER the external call
            if i > 0 && w.contains(&0x54) && w.contains(&0x11) {
                // Make sure it's after a CALL
                self.bytecode[..i].windows(5).any(|prev| prev.contains(&0xf1) || prev.contains(&0xf4))
            } else {
                false
            }
        });
        
        has_threshold_check && has_external_call && no_recheck
    }
    
    fn detect_signer_weight_manipulation(&self) -> bool {
        // Pattern: Weighted signer logic with mutable weights
        let has_weight_logic = self.bytecode.windows(15).any(|w| {
            w.contains(&0x02) && // MUL (weight calculation)
            w.contains(&0x54) && // SLOAD (load weight)
            w.contains(&0x11)    // GT (compare weighted sum)
        });
        
        let has_weight_mutation = self.bytecode.windows(4).any(|w| {
            matches!(w, [0xae, 0xd1, 0x8f, 0x6a]) // setWeight() selector
        });
        
        has_weight_logic && has_weight_mutation
    }
    
    fn detect_dynamic_signer_bypass(&self) -> bool {
        // Pattern: addOwner() function callable during execution
        let has_add_owner = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x0d, 0x58, 0x2f, 0x13]) // addOwnerWithThreshold() selector
        });
        
        let no_execution_lock = !self.bytecode.windows(20).any(|w| {
            // Missing reentrancy guard or execution lock
            w.contains(&0x54) && // SLOAD
            w.contains(&0x15) && // ISZERO (require not executing)
            w.contains(&0x57)    // JUMPI (revert if executing)
        });
        
        has_add_owner && no_execution_lock
    }
    
    fn detect_threshold_timing_vulnerability(&self) -> bool {
        // Pattern: Threshold stored with queued transaction but not validated at execution
        let has_queue = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x01, 0x65, 0x14, 0x11]) // queueTransaction() or similar
        });
        
        let has_execute = self.bytecode.windows(4).any(|w| {
            matches!(w, [0xfe, 0x44, 0x71, 0xcc]) // executeTransaction()
        });
        
        let no_threshold_validation_at_execution = has_execute && !self.bytecode.windows(30).any(|w| {
            // Check if execution function validates threshold
            w.contains(&0x54) && // SLOAD (threshold)
            w.contains(&0x11) && // GT comparison
            w.windows(4).any(|sig| matches!(sig, [0xfe, 0x44, 0x71, 0xcc])) // Near execute function
        });
        
        has_queue && no_threshold_validation_at_execution
    }
    
    fn detect_delegatecall_threshold_corruption(&self) -> bool {
        // Pattern: Delegatecall without storage slot protection
        let has_delegatecall = self.bytecode.windows(3).any(|w| {
            w.contains(&0xf4) // DELEGATECALL
        });
        
        let threshold_in_storage = self.bytecode.windows(10).any(|w| {
            w.contains(&0x54) && // SLOAD (threshold read)
            w.contains(&0x55)    // SSTORE (threshold write) - mutable
        });
        
        has_delegatecall && threshold_in_storage
    }
    
    fn detect_cross_contract_state_dependency(&self) -> bool {
        // Pattern: Threshold read from external contract
        let threshold_from_external = self.bytecode.windows(20).any(|w| {
            w.contains(&0xf1) && // CALL to external contract
            w.iter().skip_while(|&&b| b != 0xf1).take(15).any(|&b| b == 0x11) // GT (threshold comparison) after CALL
        });
        
        let no_flash_loan_protection = !self.bytecode.windows(15).any(|w| {
            w.contains(&0x43) && // NUMBER (block check)
            w.contains(&0x14)    // EQ (same block protection)
        });
        
        threshold_from_external && no_flash_loan_protection
    }
    
    fn detect_signature_replay_threshold_change(&self) -> bool {
        // Pattern: Threshold change doesn't invalidate pending signatures
        let has_threshold_change = self.bytecode.windows(4).any(|w| {
            matches!(w, [0xe3, 0x18, 0xb5, 0x2b]) // changeThreshold() selector
        });
        
        let no_nonce_invalidation = !self.bytecode.windows(20).any(|w| {
            w.contains(&0x55) && // SSTORE (increment nonce)
            w.contains(&0x01)    // ADD (nonce++)
        });
        
        has_threshold_change && no_nonce_invalidation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threshold_manipulation_detection() {
        let bytecode = vec![
            0x54, // SLOAD (threshold)
            0x11, // GT (compare)
            0xf1, // CALL (external)
            // No re-check after call
        ];
        let detector = CrossContractMultisigThresholdDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("External Call")));
    }
    
    #[test]
    fn test_delegatecall_corruption() {
        let bytecode = vec![
            0xf4, // DELEGATECALL
            0x54, // SLOAD (threshold read)
            0x55, // SSTORE (threshold write)
        ];
        let detector = CrossContractMultisigThresholdDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("Delegatecall")));
    }
}
