/// EIP-1967 Storage Slot Collision Vulnerability Detector
///
/// Detects storage collisions with EIP-1967 standard proxy storage slots.
/// EIP-1967 defines specific storage slots for proxy implementation address, admin, etc.
///
/// Standard slots (keccak256 - 1):
/// - Implementation: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
/// - Admin:          0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
/// - Beacon:         0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
///
/// Why dangerous:
/// - Application storage can collide with proxy slots
/// - Implementation address corrupted → contract broken
/// - Admin address overwritten → loss of control
/// - Upgrade mechanism destroyed
///
/// Real exploits:
/// - Multiple proxy upgrades corrupting state
/// - Loss of admin access
/// - Implementation pointer overwritten
/// - $5M+ in stuck funds from proxy bugs
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableImplementation {
///     // ❌ DANGEROUS: Storage slot 0
///     address public owner;           // slot 0
///     mapping(address => uint256) public balances; // slot 1
///     
///     // If this is used with proxy:
///     // Proxy's implementation slot might collide!
///     // Writing to balances might overwrite implementation address!
/// }
///
/// // Correct way:
/// contract SafeImplementation {
///     // ✓ Use storage gaps or explicit slots
///     uint256[50] private __gap;
///     address public owner;
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP1967CollisionVulnerability {
    pub vulnerability_type: EIP1967IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub slot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EIP1967IssueType {
    ImplementationSlotCollision,   // Collision with implementation slot
    AdminSlotCollision,            // Collision with admin slot
    BeaconSlotCollision,           // Collision with beacon slot
    ProxyStorageAccess,            // Direct access to proxy storage slots
    UnprotectedProxySlotWrite,     // Writing to proxy slot without protection
}

pub struct EIP1967CollisionDetector {
    bytecode: Vec<u8>,
}

impl EIP1967CollisionDetector {
    // EIP-1967 standard storage slots
    const IMPLEMENTATION_SLOT: &'static str = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    const ADMIN_SLOT: &'static str = "b53127684a568b3173ae13b9f8a6016e243e63b9e8ee1178d6a717850b5d6103";
    const BEACON_SLOT: &'static str = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EIP1967CollisionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_implementation_slot_access());
        vulnerabilities.extend(self.detect_admin_slot_access());
        vulnerabilities.extend(self.detect_beacon_slot_access());
        vulnerabilities.extend(self.detect_low_slot_usage());

        vulnerabilities
    }

    fn detect_implementation_slot_access(&self) -> Vec<EIP1967CollisionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(pos) = self.find_slot_access(Self::IMPLEMENTATION_SLOT) {
            vulnerabilities.push(EIP1967CollisionVulnerability {
                vulnerability_type: EIP1967IssueType::ImplementationSlotCollision,
                severity: SecuritySeverity::Critical,
                confidence: 0.95,
                description: "Access to EIP-1967 implementation slot detected".to_string(),
                exploit_scenario: format!(
                    "IMPLEMENTATION SLOT ACCESS at position {}:\n\
                    \n\
                    CRITICAL: Code accesses EIP-1967 implementation storage slot!\n\
                    \n\
                    This slot stores the implementation address in proxy contracts.\n\
                    Writing to this slot can:\n\
                    - Corrupt the implementation pointer\n\
                    - Break the proxy upgrade mechanism\n\
                    - Lock the contract permanently\n\
                    - Allow unauthorized upgrades\n\
                    \n\
                    EIP-1967 Implementation Slot:\n\
                    0x{}\n\
                    \n\
                    VULNERABLE PATTERN:\n\
                    ```solidity\n\
                    contract UnsafeImplementation {{\n\
                        // ❌ Variables starting at slot 0\n\
                        address public owner;  // slot 0\n\
                        uint256 public value;  // slot 1\n\
                        mapping(uint256 => address) public data; // slot 2\n\
                        \n\
                        function updateData(uint256 key, address value) external {{\n\
                            data[key] = value;\n\
                            // If key is specially crafted:\n\
                            // keccak256(key || 2) might equal implementation slot!\n\
                            // Implementation pointer overwritten!\n\
                        }}\n\
                    }}\n\
                    ```\n\
                    \n\
                    COLLISION ATTACK:\n\
                    ```solidity\n\
                    // Attacker finds: keccak256(attackKey || 2) == IMPLEMENTATION_SLOT\n\
                    // Then calls:\n\
                    implementation.updateData(attackKey, maliciousContract);\n\
                    \n\
                    // Result:\n\
                    // - Implementation slot overwritten\n\
                    // - Proxy now points to malicious contract\n\
                    // - Attacker controls all future calls\n\
                    ```\n\
                    \n\
                    SAFE PATTERN (OpenZeppelin):\n\
                    ```solidity\n\
                    contract SafeImplementation {{\n\
                        // ✓ Storage gap to avoid collisions\n\
                        uint256[50] private __gap;\n\
                        \n\
                        // Application storage starts after gap\n\
                        address public owner;\n\
                        uint256 public value;\n\
                    }}\n\
                    ```\n\
                    \n\
                    FIX:\n\
                    - Use storage gaps (OpenZeppelin pattern)\n\
                    - Never access slots near EIP-1967 locations\n\
                    - Use unstructured storage for proxy variables\n\
                    - Audit storage layout carefully",
                    pos, Self::IMPLEMENTATION_SLOT
                ),
                location: pos,
                slot: Self::IMPLEMENTATION_SLOT.to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_admin_slot_access(&self) -> Vec<EIP1967CollisionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(pos) = self.find_slot_access(Self::ADMIN_SLOT) {
            vulnerabilities.push(EIP1967CollisionVulnerability {
                vulnerability_type: EIP1967IssueType::AdminSlotCollision,
                severity: SecuritySeverity::Critical,
                confidence: 0.95,
                description: "Access to EIP-1967 admin slot detected".to_string(),
                exploit_scenario: format!(
                    "ADMIN SLOT ACCESS at position {}:\n\
                    \n\
                    Code accesses EIP-1967 admin storage slot!\n\
                    \n\
                    This slot stores the proxy admin address.\n\
                    Corruption causes:\n\
                    - Loss of admin control\n\
                    - Inability to upgrade\n\
                    - Permanent contract lock\n\
                    \n\
                    Admin Slot: 0x{}",
                    pos, Self::ADMIN_SLOT
                ),
                location: pos,
                slot: Self::ADMIN_SLOT.to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_beacon_slot_access(&self) -> Vec<EIP1967CollisionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(pos) = self.find_slot_access(Self::BEACON_SLOT) {
            vulnerabilities.push(EIP1967CollisionVulnerability {
                vulnerability_type: EIP1967IssueType::BeaconSlotCollision,
                severity: SecuritySeverity::High,
                confidence: 0.90,
                description: "Access to EIP-1967 beacon slot detected".to_string(),
                exploit_scenario: format!(
                    "BEACON SLOT ACCESS at position {}:\n\
                    \n\
                    Code accesses EIP-1967 beacon storage slot!\n\
                    \n\
                    Beacon Slot: 0x{}",
                    pos, Self::BEACON_SLOT
                ),
                location: pos,
                slot: Self::BEACON_SLOT.to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_low_slot_usage(&self) -> Vec<EIP1967CollisionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect SSTORE to low slots (0-100) which are risky in proxies
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if slot is low number
                if self.has_low_slot_before(i) {
                    vulnerabilities.push(EIP1967CollisionVulnerability {
                        vulnerability_type: EIP1967IssueType::ProxyStorageAccess,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Storage write to low slot - risky in proxy context".to_string(),
                        exploit_scenario: format!(
                            "LOW SLOT STORAGE at position {}:\n\
                            \n\
                            Writing to low storage slots (0-100) is risky in proxy patterns.\n\
                            \n\
                            Recommendation:\n\
                            - Use storage gaps\n\
                            - Start application storage at higher slots\n\
                            - Follow OpenZeppelin upgradeable patterns",
                            i
                        ),
                        location: i,
                        slot: "low".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn find_slot_access(&self, slot_hex: &str) -> Option<usize> {
        let slot_bytes = hex::decode(slot_hex).ok()?;
        
        // Look for PUSH32 with this exact value
        for i in 0..self.bytecode.len().saturating_sub(33) {
            if self.bytecode[i] == 0x7F { // PUSH32
                let pushed_value = &self.bytecode[i+1..i+33];
                if pushed_value == slot_bytes.as_slice() {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_low_slot_before(&self, pos: usize) -> bool {
        // Check for PUSH of small number (< 100)
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 { // PUSH1
                if i + 1 < self.bytecode.len() && self.bytecode[i+1] < 100 {
                    return true;
                }
            }
        }
        false
    }
}
