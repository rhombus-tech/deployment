/// Quadratic Funding & Voting Mechanism Detector
/// Targets: Gitcoin Grants, quadratic voting systems

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadraticMechanismVulnerability {
    pub vulnerability_type: QuadraticVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuadraticVulnType {
    GitcoinGrantSybil,
    QuadraticVotingCollusion,
    IdentityVerificationBypass,
    ContributionMatchingExploit,
}

pub struct QuadraticMechanismDetector {
    bytecode: Vec<u8>,
}

impl QuadraticMechanismDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<QuadraticMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_quadratic_mechanism() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_sybil_attack());
        vulnerabilities.extend(self.detect_collusion());

        vulnerabilities
    }

    fn is_quadratic_mechanism(&self) -> bool {
        // Look for sqrt operations (quadratic formula)
        self.bytecode.windows(1).any(|w| w[0] == 0x0A) // EXP with 0.5 exponent (sqrt)
    }

    fn detect_sybil_attack(&self) -> Vec<QuadraticMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x0A { // EXP (sqrt for quadratic)
                let no_identity = !self.bytecode[i.saturating_sub(80)..i]
                    .windows(1).any(|w| w[0] == 0xF1 || w[0] == 0xFA); // No external identity verification

                if no_identity {
                    vulnerabilities.push(QuadraticMechanismVulnerability {
                        vulnerability_type: QuadraticVulnType::GitcoinGrantSybil,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Quadratic funding without sybil resistance".to_string(),
                        exploit_scenario: "Gitcoin Sybil Attack:\n\
                            1. Quadratic matching: sqrt(sum of contributions)\n\
                            2. No proof of humanity\n\
                            3. Attacker creates 100 wallets\n\
                            4. Each contributes $1 to their project\n\
                            5. Gets sqrt(100) = 10x matching multiplier\n\
                            6. Dominates matching pool unfairly\n\
                            \n\
                            Impact: Sybils extract matching funds".to_string(),
                        remediation: "Require Gitcoin Passport or similar proof of humanity".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_collusion(&self) -> Vec<QuadraticMechanismVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x02 { // MUL (vote power calculation)
                let no_collusion_detection = !self.bytecode[i.saturating_sub(80)..i+50]
                    .windows(1).filter(|w| w[0] == 0x33).count() >= 3; // Not checking multiple addresses

                if no_collusion_detection {
                    vulnerabilities.push(QuadraticMechanismVulnerability {
                        vulnerability_type: QuadraticVulnType::QuadraticVotingCollusion,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Quadratic voting without collusion detection".to_string(),
                        exploit_scenario: "Quadratic Voting Collusion:\n\
                            1. Voters can split votes across addresses\n\
                            2. Sqrt(n) vote power per address\n\
                            3. Attackers collude to split optimally\n\
                            4. Gain disproportionate influence\n\
                            \n\
                            Impact: Voting manipulation".to_string(),
                        remediation: "Implement collusion resistance mechanisms".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}
