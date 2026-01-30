/// Protocol Upgrade Race Detector
/// Detects exploits during proxy upgrade windows

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolUpgradeRaceVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct ProtocolUpgradeRaceDetector {
    bytecode: Vec<u8>,
}

impl ProtocolUpgradeRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProtocolUpgradeRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unprotected_upgrade());
        vulnerabilities.extend(self.detect_storage_collision_risk());
        vulnerabilities.extend(self.detect_uninitialized_implementation());
        vulnerabilities
    }

    fn detect_unprotected_upgrade(&self) -> Vec<ProtocolUpgradeRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            if self.is_upgrade_function(pc) {
                if !self.has_timelock_or_delay(pc, 200) {
                    vulnerabilities.push(ProtocolUpgradeRaceVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.90,
                        description: format!(
                            "Upgrade function at PC {} has no timelock or delay. \
                            Attackers can exploit transactions in-flight during instant upgrades.",
                            pc
                        ),
                        exploit_scenario:
                            "Instant Upgrade Race Attack:\n\
                             1. User submits large deposit transaction\n\
                             2. Malicious admin sees pending transaction\n\
                             3. Admin front-runs with upgrade to malicious implementation\n\
                             4. User's deposit executes against new malicious code\n\
                             5. Malicious code steals user's funds\n\
                             6. Admin upgrades back to legitimate code\n\
                             7. Evidence of malicious code is gone\n\n\
                             Fix:\n\
                             uint256 public upgradeDelay = 2 days;\n\
                             mapping(address => uint256) public proposedUpgrades;\n\
                             \n\
                             function proposeUpgrade(address newImpl) onlyOwner {\n\
                                 proposedUpgrades[newImpl] = block.timestamp;\n\
                                 emit UpgradeProposed(newImpl, block.timestamp + upgradeDelay);\n\
                             }\n\
                             \n\
                             function executeUpgrade(address newImpl) onlyOwner {\n\
                                 require(block.timestamp >= proposedUpgrades[newImpl] + upgradeDelay);\n\
                                 _upgradeTo(newImpl);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_storage_collision_risk(&self) -> Vec<ProtocolUpgradeRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_delegatecall(pc) {
                if self.has_storage_writes_nearby(pc, 100) {
                    if !self.has_storage_gap_pattern(pc, 150) {
                        vulnerabilities.push(ProtocolUpgradeRaceVulnerability {
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "Delegatecall with storage writes at PC {} lacks storage gap protection. \
                                Upgrades can cause storage collisions, corrupting critical data.",
                                pc
                            ),
                            exploit_scenario:
                                "Storage Collision During Upgrade:\n\
                                 1. V1 contract: slot 0 = owner, slot 1 = balance\n\
                                 2. V2 adds new variable at slot 1 = newFeature\n\
                                 3. Upgrade happens\n\
                                 4. User's balance in slot 1 is now interpreted as newFeature\n\
                                 5. newFeature writes overwrite user balances\n\
                                 6. Funds are corrupted or lost\n\n\
                                 Fix:\n\
                                 contract V1 {\n\
                                     address public owner;\n\
                                     mapping(address => uint256) public balances;\n\
                                     uint256[50] private __gap;  // Reserve space!\n\
                                 }\n\
                                 \n\
                                 contract V2 is V1 {\n\
                                     uint256 public newFeature;  // Uses gap, doesn't collide\n\
                                     uint256[49] private __gap;  // Reduce gap by 1\n\
                                 }".to_string(),
                            location: pc,
                        });
                    }
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_uninitialized_implementation(&self) -> Vec<ProtocolUpgradeRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(180) {
            if self.is_upgrade_function(pc) {
                if !self.has_initialization_check_after_upgrade(pc, 200) {
                    vulnerabilities.push(ProtocolUpgradeRaceVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Upgrade at PC {} doesn't ensure new implementation is initialized. \
                            Uninitialized implementation can be front-run and taken over.",
                            pc
                        ),
                        exploit_scenario:
                            "Uninitialized Implementation Takeover:\n\
                             1. Admin deploys new implementation V2\n\
                             2. Admin calls upgrade() to point proxy to V2\n\
                             3. V2 has initialize() function but not called yet\n\
                             4. Attacker sees pending upgrade transaction\n\
                             5. Attacker front-runs and calls V2.initialize() directly\n\
                             6. Attacker becomes owner of V2 implementation\n\
                             7. Attacker can selfdestruct V2\n\
                             8. Proxy now points to destroyed implementation\n\
                             9. All proxy funds are locked\n\n\
                             Fix:\n\
                             function upgradeAndCall(address newImpl, bytes calldata data) onlyOwner {\n\
                                 _upgradeTo(newImpl);\n\
                                 if (data.length > 0) {\n\
                                     (bool success,) = newImpl.delegatecall(data);\n\
                                     require(success);\n\
                                 }\n\
                             }\n\
                             \n\
                             // Deploy and initialize atomically:\n\
                             upgradeAndCall(newImpl, abi.encodeWithSelector(IInit.initialize.selector, params));".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_upgrade_function(&self, pc: usize) -> bool {
        if pc + 60 >= self.bytecode.len() { return false; }
        // Look for SSTORE to implementation slot (EIP-1967: 0x360...33)
        for i in pc..(pc + 60).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 { // SSTORE
                return true;
            }
        }
        false
    }

    fn has_timelock_or_delay(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in (i + 1)..(i + 20).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_delegatecall(&self, pc: usize) -> bool {
        self.bytecode.get(pc) == Some(&0xf4)
    }

    fn has_storage_writes_nearby(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if self.bytecode[i] == 0x55 { return true; }
        }
        false
    }

    fn has_storage_gap_pattern(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        let mut large_push_count = 0;
        for i in start..end {
            if matches!(self.bytecode[i], 0x61..=0x63) { // PUSH2-PUSH4
                large_push_count += 1;
            }
        }
        large_push_count >= 3 // Suggests gap array
    }

    fn has_initialization_check_after_upgrade(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut has_delegatecall_after = false;
        for i in pc..end {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                has_delegatecall_after = true;
                break;
            }
        }
        has_delegatecall_after
    }
}
