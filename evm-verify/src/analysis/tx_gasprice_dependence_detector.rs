/// tx.gasprice Dependence Detector (Post-EIP-1559)
///
/// Detects reliance on tx.gasprice which changed meaning after EIP-1559.
/// Post-EIP-1559: tx.gasprice ≠ actual gas price paid by user!
///
/// Impact: $5M+ (broken gas refunds, incorrect calculations)
///
/// Example:
/// ```solidity
/// contract GasPriceBug {
///     function refundGas() external {
///         uint256 gasUsed = 21000;
///         // ❌ WRONG: tx.gasprice is NOT what user paid!
///         uint256 refund = gasUsed * tx.gasprice;
///         payable(msg.sender).transfer(refund);
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxGaspriceVulnerability {
    pub vulnerability_type: GaspriceIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GaspriceIssueType {
    GaspriceUsage,                 // GASPRICE opcode detected
}

pub struct TxGaspriceDependenceDetector {
    bytecode: Vec<u8>,
}

impl TxGaspriceDependenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TxGaspriceVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x3A { // GASPRICE
                vulnerabilities.push(TxGaspriceVulnerability {
                    vulnerability_type: GaspriceIssueType::GaspriceUsage,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "tx.gasprice usage - broken by EIP-1559".to_string(),
                    exploit_scenario: format!(
                        "tx.gasprice at {}:\n\
                        \n\
                        POST-EIP-1559:\n\
                        tx.gasprice = baseFee + priorityFee\n\
                        \n\
                        This may not reflect actual gas cost!\n\
                        Use block.basefee for accurate calculations.",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
