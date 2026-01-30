// Elliptic Curve Twist Attack Detector
// Detects vulnerabilities to invalid curve point attacks

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EllipticCurveTwistVulnerability {
    pub location: usize,
    pub confidence: f32,
    pub vulnerability_type: String,
    pub description: String,
}

pub struct EllipticCurveTwistDetector {
    bytecode: Vec<u8>,
}

impl EllipticCurveTwistDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EllipticCurveTwistVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_invalid_point_acceptance());
        vulnerabilities.extend(self.detect_small_subgroup_attacks());
        vulnerabilities
    }

    fn detect_invalid_point_acceptance(&self) -> Vec<EllipticCurveTwistVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        while i < self.bytecode.len() {
            if i + 50 < self.bytecode.len() {
                // ECADD (0x06) or ECMUL (0x07) precompile calls
                if self.bytecode[i] == 0xf1 && i + 10 < self.bytecode.len() {
                    if self.bytecode.get(i + 5) == Some(&0x06) || self.bytecode.get(i + 5) == Some(&0x07) {
                        let mut has_point_validation = false;
                        
                        for j in (i.saturating_sub(30))..i {
                            if j < self.bytecode.len() && self.bytecode[j] == 0x20 { // SHA3
                                has_point_validation = true;
                            }
                        }

                        if !has_point_validation {
                            vulns.push(EllipticCurveTwistVulnerability {
                                location: i,
                                confidence: 0.82,
                                vulnerability_type: "InvalidCurvePointAcceptance".to_string(),
                                description: format!(
                                    "Invalid curve point risk at PC {}: EC operations without curve equation validation. \
                                    Attacker can provide points on twist curve causing incorrect computation. \
                                    Add point-on-curve checks before EC operations.",
                                    i
                                ),
                            });
                        }
                    }
                }
            }
            i += 1;
        }
        vulns
    }

    fn detect_small_subgroup_attacks(&self) -> Vec<EllipticCurveTwistVulnerability> {
        let mut vulns = Vec::new();
        let mut i = 0;

        while i < self.bytecode.len() {
            if i + 40 < self.bytecode.len() {
                if self.bytecode[i] == 0xf1 {
                    if self.bytecode.get(i + 5) == Some(&0x07) { // ECMUL
                        vulns.push(EllipticCurveTwistVulnerability {
                            location: i,
                            confidence: 0.78,
                            vulnerability_type: "SmallSubgroupAttack".to_string(),
                            description: format!(
                                "Small subgroup attack at PC {}: ECMUL without subgroup order verification. \
                                Attacker can provide low-order points reducing key space. Add cofactor multiplication checks.",
                                i
                            ),
                        });
                    }
                }
            }
            i += 1;
        }
        vulns
    }
}
