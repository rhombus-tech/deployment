/// Constructor Failure/Revert Silencing Detector
///
/// Detects contracts that deploy despite constructor failures.
/// Silent constructor failures leave contracts in unexpected/broken state.
///
/// Why dangerous:
/// - Constructor reverts but contract still deployed (pre-Byzantium)
/// - Uninitialized critical state variables
/// - Contract appears deployed but is broken
/// - Users interact with broken contract
///
/// Real exploits:
/// - **Parity Wallet: $280M frozen** - Constructor init failure
/// - Multiple proxy initialization bugs
/// - Broken state from failed constructors
///
/// Example vulnerability:
/// ```solidity
/// contract BrokenDeployment {
///     address public immutable owner;
///     IERC20 public immutable token;
///     
///     constructor(address _token) {
///         token = IERC20(_token);
///         
///         // ❌ If this fails, contract still deploys but broken!
///         require(token.totalSupply() > 0, "Invalid token");
///         
///         owner = msg.sender;
///         // If require failed, owner = address(0)!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorFailureVulnerability {
    pub vulnerability_type: ConstructorIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstructorIssueType {
    UncheckedExternalCall,         // External call in constructor unchecked
    RequireAfterStateChange,       // State changed before require
    ImmutableNotInitialized,       // Immutable variable may not be set
    MissingZeroAddressCheck,       // No validation of critical addresses
}

pub struct ConstructorFailureDetector {
    bytecode: Vec<u8>,
}

impl ConstructorFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConstructorFailureVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect constructor patterns (bytecode before runtime starts)
        vulnerabilities.extend(self.detect_constructor_external_calls());
        vulnerabilities.extend(self.detect_unsafe_constructor_pattern());

        vulnerabilities
    }

    fn detect_constructor_external_calls(&self) -> Vec<ConstructorFailureVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Constructor typically ends with CODECOPY for runtime code
        // Look for CALL/STATICCALL before that point
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA { // CALL or STATICCALL
                // Check if this is in constructor (heuristic: before large CODECOPY)
                if self.might_be_in_constructor(i) {
                    vulnerabilities.push(ConstructorFailureVulnerability {
                        vulnerability_type: ConstructorIssueType::UncheckedExternalCall,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.60,
                        description: "External call in constructor - verify failure handling".to_string(),
                        exploit_scenario: format!(
                            "CONSTRUCTOR EXTERNAL CALL at position {}:\n\
                            \n\
                            External call during construction can fail silently.\n\
                            If call fails but not checked, contract deploys in broken state.\n\
                            \n\
                            PARITY WALLET INCIDENT ($280M):\n\
                            Library initialization failed but wallet deployed anyway.\n\
                            Users deposited funds into broken contract.\n\
                            Funds permanently locked.\n\
                            \n\
                            SAFE PATTERN:\n\
                            ```solidity\n\
                            constructor(address _dependency) {{\n\
                                // ✓ Check external call success\n\
                                (bool success,) = _dependency.call(\n\
                                    abi.encodeWithSignature('validate()')\n\
                                );\n\
                                require(success, 'Dependency init failed');\n\
                            }}\n\
                            ```",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_unsafe_constructor_pattern(&self) -> Vec<ConstructorFailureVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for REVERT in what might be constructor code
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xFD { // REVERT
                if self.might_be_in_constructor(i) {
                    vulnerabilities.push(ConstructorFailureVulnerability {
                        vulnerability_type: ConstructorIssueType::RequireAfterStateChange,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.55,
                        description: "Conditional revert in constructor - verify state consistency".to_string(),
                        exploit_scenario: "Constructor has validation that may revert. Ensure all critical state is set before any require statements.".to_string(),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn might_be_in_constructor(&self, pos: usize) -> bool {
        // Heuristic: constructor is typically in first ~30% of bytecode
        // and before CODECOPY of runtime code
        pos < self.bytecode.len() / 3
    }
}
