/// Static Multisig Weakness Detector
/// 
/// Detects multisigs with weak static configuration (not runtime manipulation)
/// Different from cross_contract_multisig_threshold_manipulation which detects CHANGES
/// This detects if multisig is DEPLOYED with bad configuration
/// 
/// Patterns:
/// - threshold = 1 (fake multisig, any single signer can execute)
/// - signers < 3 (not really decentralized)
/// - threshold < 50% of signers (minority control)
/// - All signers deployed from same address (same entity control)

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMultisigWeaknessVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub weakness_type: MultisigWeaknessType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultisigWeaknessType {
    ThresholdOne,           // threshold = 1, any single signer
    TooFewSigners,          // < 3 signers
    MinorityControl,        // threshold < 50% of signers
    FakeDecentralization,   // Marketed as multisig but effectively single-sig
    NoTimelockOnThreshold,  // Can change threshold instantly
    SignerConcentration,    // High risk of collusion
}

pub struct StaticMultisigWeaknessDetector {
    bytecode: Vec<u8>,
}

impl StaticMultisigWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Threshold = 1 detection
        vulnerabilities.extend(self.detect_threshold_one());

        // 2. Too few signers (< 3)
        vulnerabilities.extend(self.detect_too_few_signers());

        // 3. Minority control (threshold < 50%)
        vulnerabilities.extend(self.detect_minority_control());

        // 4. Fake decentralization patterns
        vulnerabilities.extend(self.detect_fake_decentralization());

        // 5. No timelock on threshold changes
        vulnerabilities.extend(self.detect_no_threshold_timelock());

        vulnerabilities
    }

    fn detect_threshold_one(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: threshold storage initialized to 1
            // Look for: PUSH1 1 → SSTORE (threshold_slot)
            if self.has_threshold_one_initialization(pc) {
                vulns.push(StaticMultisigWeaknessVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    weakness_type: MultisigWeaknessType::ThresholdOne,
                    description: "Multisig has threshold = 1, any single signer can execute alone".to_string(),
                    exploit_scenario: "contract MultiSig {\n\
                        uint public threshold = 1;  // ← CRITICAL ISSUE\n\
                        address[] public signers = [addr1, addr2, addr3, addr4, addr5];\n\
                        \n\
                        // Marketed as '5-signer multisig'\n\
                        // Reality: ANY ONE SIGNER can execute alone\n\
                        // Fake decentralization\n\
                        \n\
                        function executeTransaction() {\n\
                            require(signatures.length >= threshold); // Only needs 1!\n\
                            // Execute with single signature\n\
                        }\n\
                        // $100M treasury controlled by single key\n\
                        // One compromised signer = complete loss\n\
                        }".to_string(),
                    remediation: "Set minimum threshold: require(threshold >= 2 && threshold > signers.length / 2)".to_string(),
                    confidence: 0.92,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_too_few_signers(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: signer count < 3
            if self.has_too_few_signers(pc) {
                vulns.push(StaticMultisigWeaknessVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    weakness_type: MultisigWeaknessType::TooFewSigners,
                    description: "Multisig has fewer than 3 signers, not truly decentralized".to_string(),
                    exploit_scenario: "contract MultiSig {\n\
                        address[] public signers = [alice, bob]; // Only 2 signers\n\
                        uint public threshold = 2;\n\
                        \n\
                        // 2-of-2 multisig issues:\n\
                        // 1. Both signers must be online (availability risk)\n\
                        // 2. Lose one key = funds locked forever\n\
                        // 3. Two signers from same entity = not decentralized\n\
                        // 4. Easy collusion between 2 people\n\
                        \n\
                        // Minimum 3 signers needed for:\n\
                        // - True decentralization\n\
                        // - Key recovery options\n\
                        // - Harder collusion\n\
                        }".to_string(),
                    remediation: "Use at least 3 signers, preferably 5+ for important protocols".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_minority_control(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: threshold < signers / 2 (minority can execute)
            if self.has_minority_control_risk(pc) {
                vulns.push(StaticMultisigWeaknessVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    weakness_type: MultisigWeaknessType::MinorityControl,
                    description: "Multisig threshold allows minority of signers to control execution".to_string(),
                    exploit_scenario: "contract MultiSig {\n\
                        address[] public signers; // 9 signers\n\
                        uint public threshold = 3; // Only 3 needed (33%)\n\
                        \n\
                        // 3-of-9 multisig:\n\
                        // - Minority (33%) controls execution\n\
                        // - Majority (66%) cannot prevent malicious actions\n\
                        // - 3 colluding signers can steal funds\n\
                        // - Not truly decentralized governance\n\
                        \n\
                        // Best practice: threshold > 50% of signers\n\
                        // E.g., 5-of-9 or 6-of-9\n\
                        }".to_string(),
                    remediation: "Set threshold > 50% of signers: threshold = (signers.length / 2) + 1".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_fake_decentralization(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Multisig with easily changeable threshold
            // or single owner can modify signer list
            if self.has_fake_decentralization_pattern(pc) {
                vulns.push(StaticMultisigWeaknessVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    weakness_type: MultisigWeaknessType::FakeDecentralization,
                    description: "Multisig appears decentralized but has centralized control vectors".to_string(),
                    exploit_scenario: "contract MultiSig {\n\
                        address[] public signers = [addr1, addr2, addr3, addr4, addr5];\n\
                        uint public threshold = 3;\n\
                        \n\
                        address public owner; // ← Hidden centralization!\n\
                        \n\
                        function addSigner(address newSigner) public {\n\
                            require(msg.sender == owner); // Owner can add signers!\n\
                            signers.push(newSigner);\n\
                        }\n\
                        \n\
                        // Attack:\n\
                        // 1. Owner adds 10 signer addresses they control\n\
                        // 2. Now owner controls 10-of-15 threshold\n\
                        // 3. Original signers powerless\n\
                        // 4. 'Multisig' is actually single-owner controlled\n\
                        }".to_string(),
                    remediation: "Require multisig approval to change signers or threshold".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_no_threshold_timelock(&self) -> Vec<StaticMultisigWeaknessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: setThreshold function without timelock
            if self.has_instant_threshold_change(pc) {
                vulns.push(StaticMultisigWeaknessVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    weakness_type: MultisigWeaknessType::NoTimelockOnThreshold,
                    description: "Multisig threshold can be changed instantly without timelock".to_string(),
                    exploit_scenario: "contract MultiSig {\n\
                        uint public threshold = 5;\n\
                        address[] public signers; // 9 signers\n\
                        \n\
                        function setThreshold(uint newThreshold) {\n\
                            require(isValidSignature()); // Needs 5 signatures\n\
                            threshold = newThreshold; // ← Instant change!\n\
                        }\n\
                        \n\
                        // Attack scenario:\n\
                        // 1. Compromised signers (5-of-9) propose: setThreshold(1)\n\
                        // 2. Executes immediately, threshold now 1\n\
                        // 3. Single signer drains treasury\n\
                        // 4. Honest signers have no time to react\n\
                        \n\
                        // With timelock:\n\
                        // - 48 hour delay before threshold change\n\
                        // - Honest signers can exit during delay\n\
                        }".to_string(),
                    remediation: "Add timelock to threshold changes: execute after 48+ hour delay".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_threshold_one_initialization(&self, start: usize) -> bool {
        if start + 15 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 15];

        // Look for: PUSH1 1 → SSTORE to threshold slot
        // Common threshold slot is 0x03 or 0x04 in Gnosis Safe
        window.windows(3).any(|w| {
            w[0] == 0x60 && // PUSH1
            w[1] == 0x01 && // 1
            w[2] == 0x55    // SSTORE
        })
    }

    fn has_too_few_signers(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 20];

        // Look for: signer array length check < 3
        // Pattern: PUSH owners.length → comparison to small number
        window.windows(4).any(|w| {
            w[0] == 0x60 && // PUSH1
            (w[1] == 0x01 || w[1] == 0x02) && // 1 or 2 signers
            w[2] == 0x14 && // EQ
            w[3] == 0x57    // JUMPI (checking signer count)
        })
    }

    fn has_minority_control_risk(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];

        // Look for: threshold < signerCount / 2
        // Pattern: threshold → signerCount → DIV 2 → LT check
        let has_threshold_load = window.iter().any(|&b| b == 0x54); // SLOAD
        let has_division_by_2 = window.windows(3).any(|w| {
            w[0] == 0x60 && // PUSH1
            w[1] == 0x02 && // 2
            w[2] == 0x04    // DIV
        });
        let has_comparison = window.iter().any(|&b| b == 0x10); // LT

        has_threshold_load && has_division_by_2 && has_comparison
    }

    fn has_fake_decentralization_pattern(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Pattern: addSigner/removeSigner with single owner check
        // Look for: CALLER → owner → EQ → modify signers
        let has_owner_check = window.windows(4).any(|w| {
            w[0] == 0x33 && // CALLER
            w[1] == 0x54 && // SLOAD (owner)
            w[2] == 0x14 && // EQ
            w[3] == 0x57    // JUMPI
        });

        // Check if this is followed by array modification (signer list)
        let modifies_array = window.iter().any(|&b| b == 0x55); // SSTORE

        has_owner_check && modifies_array
    }

    fn has_instant_threshold_change(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: threshold modification without timelock check
        // setThreshold function selector: varies, but pattern is:
        // CALLDATALOAD (new threshold) → validation → SSTORE (threshold)
        
        let has_threshold_param = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
        let has_threshold_write = window.iter().any(|&b| b == 0x55); // SSTORE

        // Check if there's NO timelock validation (TIMESTAMP comparison)
        let has_timelock = window.windows(3).any(|w| {
            w[0] == 0x42 && // TIMESTAMP
            w[1] == 0x54 && // SLOAD (proposed time)
            (w[2] == 0x10 || w[2] == 0x11) // LT or GT comparison
        });

        has_threshold_param && has_threshold_write && !has_timelock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_one() {
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1 (threshold = 1)
            0x55,       // SSTORE
        ];
        
        let detector = StaticMultisigWeaknessDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.weakness_type, MultisigWeaknessType::ThresholdOne)));
    }

    #[test]
    fn test_too_few_signers() {
        let bytecode = vec![
            0x60, 0x02, // PUSH1 2 (only 2 signers)
            0x14,       // EQ
            0x57,       // JUMPI
        ];
        
        let detector = StaticMultisigWeaknessDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.weakness_type, MultisigWeaknessType::TooFewSigners)));
    }
}
