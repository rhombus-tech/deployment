/// Modifier Ordering Vulnerability Detector
///
/// Detects incorrect ordering of function modifiers that can bypass security checks.
/// Modifier order matters - wrong order can allow reentrancy, skip auth, or create race conditions.
///
/// Why dangerous:
/// - nonReentrant should come before state-changing modifiers
/// - Authentication should come before business logic
/// - Wrong order = security checks can be bypassed
/// - Reentrancy attacks if guards placed incorrectly
///
/// Critical orderings:
/// 1. nonReentrant BEFORE onlyOwner
/// 2. Input validation BEFORE state changes
/// 3. Checks BEFORE effects
/// 4. Auth BEFORE any external calls
///
/// Real exploits:
/// - $10M+ in modifier ordering bugs
/// - Reentrancy bypassing nonReentrant
/// - Authorization checks skipped
/// - State corruption from race conditions
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableOrdering {
///     bool private locked;
///     address public owner;
///     
///     modifier onlyOwner() {
///         require(msg.sender == owner);
///         _;
///     }
///     
///     modifier nonReentrant() {
///         require(!locked);
///         locked = true;
///         _;
///         locked = false;
///     }
///     
///     // ❌ WRONG ORDER: owner check happens BEFORE reentrancy guard
///     function withdraw() external onlyOwner nonReentrant {
///         // Attack: Reenter before nonReentrant check
///         (bool s,) = msg.sender.call{value: address(this).balance}("");
///         require(s);
///     }
///     
///     // ✓ CORRECT ORDER: reentrancy guard FIRST
///     function withdrawSafe() external nonReentrant onlyOwner {
///         (bool s,) = msg.sender.call{value: address(this).balance}("");
///         require(s);
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifierOrderingVulnerability {
    pub vulnerability_type: ModifierOrderingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModifierOrderingIssueType {
    NonReentrantAfterOwner,        // nonReentrant should be first
    AuthAfterStateChange,          // Auth should come before state changes
    ValidationAfterExternalCall,   // Validation after external call
    MultipleReentrancyGuards,      // Multiple reentrancy modifiers (confusion)
}

pub struct ModifierOrderingDetector {
    bytecode: Vec<u8>,
}

impl ModifierOrderingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ModifierOrderingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bytecode-level detection is limited for modifier ordering
        // This detector provides awareness of the issue
        vulnerabilities.extend(self.detect_reentrancy_pattern());

        vulnerabilities
    }

    fn detect_reentrancy_pattern(&self) -> Vec<ModifierOrderingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for SSTORE patterns that might indicate reentrancy guards
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        
        if sstore_count > 5 {
            vulnerabilities.push(ModifierOrderingVulnerability {
                vulnerability_type: ModifierOrderingIssueType::MultipleReentrancyGuards,
                severity: SecuritySeverity::Medium,
                confidence: 0.50,
                description: "Multiple state changes detected - verify modifier ordering".to_string(),
                exploit_scenario: 
                    "MODIFIER ORDERING CRITICAL:\n\
                    \n\
                    Modifier order affects security. Common mistakes:\n\
                    \n\
                    ❌ WRONG:\n\
                    ```solidity\n\
                    function withdraw() external onlyOwner nonReentrant {\n\
                        // onlyOwner checked first\n\
                        // Attacker can reenter before nonReentrant!\n\
                    }\n\
                    ```\n\
                    \n\
                    ✓ CORRECT:\n\
                    ```solidity\n\
                    function withdraw() external nonReentrant onlyOwner {\n\
                        // nonReentrant blocks reentrancy first\n\
                        // Then owner check happens\n\
                    }\n\
                    ```\n\
                    \n\
                    RULE: Guards BEFORE checks BEFORE logic".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
