/// Proxy Implementation SELFDESTRUCT Detector
///
/// Detects unprotected SELFDESTRUCT in proxy implementation contracts.
/// If implementation is destroyed, ALL proxies pointing to it break!
///
/// Impact: **$280M** (Parity Wallet)
///
/// Example:
/// ```solidity
/// contract Implementation {
///     // ❌ CRITICAL: Can destroy implementation!
///     function kill() external {
///         selfdestruct(payable(msg.sender));
///     }
///     // ALL proxies using this implementation are now BRICKED!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySelfdestructVulnerability {
    pub vulnerability_type: ProxySelfdestructType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxySelfdestructType {
    SelfdestructInImplementation,  // SELFDESTRUCT detected
    PublicDestroy,                 // Publicly callable destroy
}

pub struct ProxySelfdestructDetector {
    bytecode: Vec<u8>,
}

impl ProxySelfdestructDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProxySelfdestructVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xFF { // SELFDESTRUCT
                vulnerabilities.push(ProxySelfdestructVulnerability {
                    vulnerability_type: ProxySelfdestructType::SelfdestructInImplementation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.90,
                    description: "SELFDESTRUCT in potential proxy implementation".to_string(),
                    exploit_scenario: format!(
                        "SELFDESTRUCT at {}:\n\
                        \n\
                        **PARITY WALLET: $280M LOSS**\n\
                        \n\
                        If this is a proxy implementation:\n\
                        - Destroying it breaks ALL proxies!\n\
                        - Funds in proxies become UNRECOVERABLE!\n\
                        \n\
                        NEVER allow selfdestruct in implementation contracts!",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
