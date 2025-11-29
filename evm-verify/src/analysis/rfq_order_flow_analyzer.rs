/// RFQ (Request-For-Quote) & Private Order Flow Vulnerability Analyzer
/// Targets: CoW Protocol, 1inch Fusion, UniswapX, 0x Protocol
/// Market: Billions in private MEV orderflow

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFQOrderFlowVulnerability {
    pub vulnerability_type: RFQVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RFQVulnType {
    SolverManipulation,
    OrderStealing,
    PrivateMempoolFrontRunning,
    SolverCollusion,
    QuoteStaleness,
    FillerCartelFormation,
    SignatureReplayRFQ,
    NonceManipulation,
}

pub struct RFQOrderFlowAnalyzer {
    bytecode: Vec<u8>,
}

impl RFQOrderFlowAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RFQOrderFlowVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_rfq_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_solver_manipulation());
        vulnerabilities.extend(self.detect_order_stealing());
        vulnerabilities.extend(self.detect_quote_staleness());
        vulnerabilities.extend(self.detect_solver_collusion());

        vulnerabilities
    }

    fn is_rfq_contract(&self) -> bool {
        let rfq_signatures = [
            &[0x13, 0xd7, 0x9a, 0x0b][..], // fillRFQOrder()
            &[0xb4, 0xf6, 0x25, 0x96][..], // settleOrders() - CoW
            &[0x64, 0x61, 0x73, 0x74][..], // execute() - Fusion
        ];

        rfq_signatures.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_solver_manipulation(&self) -> Vec<RFQOrderFlowVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x33 { // CALLER (solver check)
                let single_solver_check = !self.bytecode[i+1..i+80]
                    .windows(1).filter(|w| w[0] == 0x14).count() >= 2; // Only one EQ check

                if single_solver_check {
                    vulnerabilities.push(RFQOrderFlowVulnerability {
                        vulnerability_type: RFQVulnType::SolverManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "RFQ settlement allows single solver without competition".to_string(),
                        exploit_scenario: "Solver Manipulation:\n\
                            1. User submits RFQ order to CoW Protocol\n\
                            2. Only approved solver can fill\n\
                            3. Solver sees better price available (1% improvement)\n\
                            4. Fills at quoted price, pockets 1% difference\n\
                            5. User gets worse execution than possible\n\
                            6. Systematic profit extraction from users\n\
                            \n\
                            Real issue: Centralized solver selection".to_string(),
                        remediation: "Add solver competition:\n\
                            1. Multiple solver verification\n\
                            2. Best execution guarantees\n\
                            3. Solver reputation system\n\
                            4. Slashing for poor execution\n\
                            5. Public solver auctions".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_order_stealing(&self) -> Vec<RFQOrderFlowVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x20 { // SHA3 (signature hash)
                let no_nonce_check = !self.bytecode[i.saturating_sub(50)..i+50]
                    .windows(1).filter(|w| w[0] == 0x54).count() >= 2; // Not checking nonce storage

                if no_nonce_check {
                    vulnerabilities.push(RFQOrderFlowVulnerability {
                        vulnerability_type: RFQVulnType::OrderStealing,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "RFQ orders can be front-run and stolen without proper nonce tracking".to_string(),
                        exploit_scenario: "RFQ Order Theft:\n\
                            1. User signs RFQ order for 1 ETH → 3000 USDC\n\
                            2. Submits to private mempool\n\
                            3. Malicious solver sees order\n\
                            4. Front-runs with own transaction filling order\n\
                            5. Steals user's trading opportunity\n\
                            6. User's order fails or gets worse price\n\
                            \n\
                            Impact: Private orderflow not actually private".to_string(),
                        remediation: "Prevent order theft:\n\
                            1. Nonce-based replay protection\n\
                            2. Deadline timestamps\n\
                            3. Solver authorization checks\n\
                            4. Encrypted order submission\n\
                            5. MEV protection mechanisms".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_quote_staleness(&self) -> Vec<RFQOrderFlowVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP check
                let weak_staleness = !self.bytecode[i+1..i+30]
                    .windows(2).any(|w| w[0] == 0x10 && w[1] == 0x15); // LT + ISZERO (strict deadline)

                if weak_staleness {
                    vulnerabilities.push(RFQOrderFlowVulnerability {
                        vulnerability_type: RFQVulnType::QuoteStaleness,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "RFQ quotes accepted without strict freshness requirements".to_string(),
                        exploit_scenario: "Stale Quote Exploitation:\n\
                            1. User gets quote: 1 ETH = 3000 USDC\n\
                            2. Quote valid for 5 minutes\n\
                            3. Market moves: ETH now worth 3100 USDC\n\
                            4. Solver still fills at 3000 USDC (old quote)\n\
                            5. User loses 100 USDC to stale pricing\n\
                            6. Solver/protocol captures price movement\n\
                            \n\
                            Impact: Users get outdated prices".to_string(),
                        remediation: "Enforce quote freshness:\n\
                            1. Strict deadlines (30-60 seconds max)\n\
                            2. Price deviation checks\n\
                            3. Market volatility adjustments\n\
                            4. Real-time price verification\n\
                            5. Reject quotes during high volatility".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_solver_collusion(&self) -> Vec<RFQOrderFlowVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.bytecode[i] == 0xF1 { // CALL (solver execution)
                let multiple_calls = self.bytecode[i+1..i+150]
                    .windows(1).filter(|w| w[0] == 0xF1).count() >= 2;

                let no_independence_check = !self.bytecode[i.saturating_sub(80)..i+80]
                    .windows(1).filter(|w| w[0] == 0x33).count() >= 3; // Not checking multiple addresses

                if multiple_calls && no_independence_check {
                    vulnerabilities.push(RFQOrderFlowVulnerability {
                        vulnerability_type: RFQVulnType::SolverCollusion,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Multiple solvers can collude without independence verification".to_string(),
                        exploit_scenario: "Solver Cartel Formation:\n\
                            1. Protocol uses 5 'independent' solvers\n\
                            2. No verification solvers are actually independent\n\
                            3. All 5 solvers controlled by same entity\n\
                            4. Fake competition for orders\n\
                            5. Cartel provides worse execution systematically\n\
                            6. Splits extracted value among members\n\
                            \n\
                            Real risk: Solver centralization in practice".to_string(),
                        remediation: "Prevent solver collusion:\n\
                            1. Verify solver independence on-chain\n\
                            2. Different ownership structures\n\
                            3. Geographic/entity diversification\n\
                            4. Monitor for correlated behavior\n\
                            5. Open competition for solver slots".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_solver_manipulation() {
        let bytecode = vec![
            0x33, // CALLER
            0x14, // EQ (single solver)
            0x15, 0x57, // ISZERO + JUMPI
        ];
        
        let analyzer = RFQOrderFlowAnalyzer::new(bytecode);
        let vulns = analyzer.detect_solver_manipulation();
        
        assert!(!vulns.is_empty());
    }
}
