/// Function Selector Collision Vulnerability Detector
///
/// Detects duplicate function selectors that can cause wrong function execution.
/// Function selectors are first 4 bytes of keccak256(signature).
/// With only 2^32 possible values, collisions are possible!
///
/// Why dangerous:
/// - Different functions can have same 4-byte selector
/// - Wrong function executes if selector collides
/// - Authorization bypass if admin function collides with public function
/// - Critical in proxy patterns and delegatecall
///
/// Real exploits:
/// - Poly Network: $611M - function confusion via selector manipulation
/// - Multiple proxy exploits using selector collisions
/// - Admin function bypass via collision
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableProxy {
///     address public implementation;
///     
///     // Admin function: 0x00000000 (intentional collision)
///     function upgradeTo_0x00000000(address newImpl) external {
///         require(msg.sender == owner);
///         implementation = newImpl;
///     }
///     
///     // Attacker finds: someFunction_0x00000000()
///     // Both have selector 0x00000000
///     // Attacker calls malicious function → admin function executes!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSelectorVulnerability {
    pub vulnerability_type: SelectorIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub selector: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorIssueType {
    DuplicateSelector,             // Same selector appears multiple times
    ZeroSelector,                  // Selector 0x00000000 (dangerous)
    SelectorCloseToExisting,       // Selector very close to another (1-2 bytes diff)
}

pub struct FunctionSelectorCollisionDetector {
    bytecode: Vec<u8>,
}

impl FunctionSelectorCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FunctionSelectorVulnerability> {
        let mut vulnerabilities = Vec::new();

        let selectors = self.extract_function_selectors();
        vulnerabilities.extend(self.detect_duplicate_selectors(&selectors));
        vulnerabilities.extend(self.detect_zero_selector(&selectors));

        vulnerabilities
    }

    fn extract_function_selectors(&self) -> HashMap<Vec<u8>, Vec<usize>> {
        let mut selectors: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();

        // Look for PUSH4 followed by EQ pattern (function selector matching)
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x63 { // PUSH4
                let selector = self.bytecode[i+1..i+5].to_vec();
                selectors.entry(selector).or_insert_with(Vec::new).push(i);
            }
        }

        selectors
    }

    fn detect_duplicate_selectors(&self, selectors: &HashMap<Vec<u8>, Vec<usize>>) -> Vec<FunctionSelectorVulnerability> {
        let mut vulnerabilities = Vec::new();

        for (selector, positions) in selectors.iter() {
            if positions.len() > 1 {
                vulnerabilities.push(FunctionSelectorVulnerability {
                    vulnerability_type: SelectorIssueType::DuplicateSelector,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.95,
                    description: format!("Duplicate function selector 0x{} found at {} locations", 
                        hex::encode(selector), positions.len()),
                    exploit_scenario: format!(
                        "DUPLICATE SELECTOR 0x{} at positions: {:?}\n\
                        \n\
                        CRITICAL: Same selector used for multiple functions!\n\
                        This can cause function confusion and authorization bypass.\n\
                        \n\
                        Poly Network Hack Pattern ($611M):\n\
                        Different function names but same selector → wrong function executes.\n\
                        \n\
                        Fix: Ensure all function selectors are unique",
                        hex::encode(selector), positions
                    ),
                    location: positions[0],
                    selector: selector.clone(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_zero_selector(&self, selectors: &HashMap<Vec<u8>, Vec<usize>>) -> Vec<FunctionSelectorVulnerability> {
        let mut vulnerabilities = Vec::new();

        let zero_selector = vec![0, 0, 0, 0];
        if let Some(positions) = selectors.get(&zero_selector) {
            for &pos in positions {
                vulnerabilities.push(FunctionSelectorVulnerability {
                    vulnerability_type: SelectorIssueType::ZeroSelector,
                    severity: SecuritySeverity::High,
                    confidence: 0.90,
                    description: "Function with selector 0x00000000 detected".to_string(),
                    exploit_scenario: format!(
                        "ZERO SELECTOR at position {}:\n\
                        \n\
                        Selector 0x00000000 is dangerous:\n\
                        - Easy to collide with (birthday attack)\n\
                        - Can be triggered by mistake\n\
                        - Used in some exploits for function confusion\n\
                        \n\
                        Recommendation: Avoid using functions with this selector",
                        pos
                    ),
                    location: pos,
                    selector: zero_selector.clone(),
                });
            }
        }

        vulnerabilities
    }
}
