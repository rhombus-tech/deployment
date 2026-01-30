use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrisonerDilemmaVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PrisonerDilemmaGriefingDetector {
    bytecode: Vec<u8>,
}

impl PrisonerDilemmaGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PrisonerDilemmaVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_mutual_defection_incentive());
        vulnerabilities.extend(self.detect_first_mover_disadvantage());
        vulnerabilities.extend(self.detect_coordination_failure());

        vulnerabilities
    }

    fn detect_mutual_defection_incentive(&self) -> Vec<PrisonerDilemmaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (participant action)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_payout_logic = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2; // Conditional payouts
                let has_multiple_participants = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                
                if has_payout_logic && has_multiple_participants {
                    let has_cooperation_incentive = window.iter().filter(|&&b| b == 0x02).count() >= 3; // MUL (bonus)
                    let has_punishment = window.iter().any(|&b| b == 0x03); // SUB (penalty)
                    
                    if !has_cooperation_incentive || !has_punishment {
                        vulns.push(PrisonerDilemmaVulnerability {
                            pc,
                            vulnerability_type: "MutualDefectionIncentive".to_string(),
                            description: format!(
                                "Multi-party payout at PC {} creates prisoner's dilemma. Game theory: rational participants defect even when cooperation yields better \
                                collective outcome. Example: liquidity pool exit, if everyone cooperates (gradual withdrawal), pool stable, everyone gets fair value. If \
                                one defects (rush exit), gets better price, others lose. Result: everyone rushes to exit (bank run). Missing: tit-for-tat enforcement, \
                                iterated game structure, defection punishment mechanism, cooperation rewards > defection payoff. Should implement: locked withdrawal \
                                periods, exit fees benefiting remaining participants, reputation system.",
                                pc
                            ),
                            confidence: 0.83,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_first_mover_disadvantage(&self) -> Vec<PrisonerDilemmaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (ordering/timing)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_sequential_logic = window.iter().any(|&b| b == 0x14); // EQ (first mover check)
                let has_payout_difference = window.iter().filter(|&&b| b == 0x04).count() >= 2; // Multiple DIV
                
                if has_sequential_logic && has_payout_difference {
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256
                    
                    if !has_commit_reveal {
                        vulns.push(PrisonerDilemmaVulnerability {
                            pc,
                            vulnerability_type: "FirstMoverDisadvantage".to_string(),
                            description: format!(
                                "Sequential action mechanism at PC {} penalizes first mover. Attack: contract requires participants to reveal decisions sequentially, \
                                first mover reveals their choice (cooperate/defect), second mover observes and always chooses optimal counter (defect if first cooperated). \
                                First mover always loses. Example: sealed bid auction without commit-reveal, MEV scenario where first trader reveals strategy. Missing: \
                                simultaneous reveal mechanism, commit-reveal scheme, encrypted commitments. Should use: all participants commit hash(action + nonce), then \
                                reveal simultaneously.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_coordination_failure(&self) -> Vec<PrisonerDilemmaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (group reward calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_threshold_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_multiple_participants = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                
                if has_threshold_check && has_multiple_participants {
                    let has_communication_mechanism = window.iter().any(|&b| b == 0xF1); // CALL (signaling)
                    let has_fallback_payout = window.iter().filter(|&&b| b == 0x02).count() >= 2;
                    
                    if !has_communication_mechanism && !has_fallback_payout {
                        vulns.push(PrisonerDilemmaVulnerability {
                            pc,
                            vulnerability_type: "CoordinationFailure".to_string(),
                            description: format!(
                                "Threshold-based group payout at PC {} lacks coordination mechanism. Attack: contract requires N of M participants to cooperate for \
                                group reward, no communication allowed, rational participant thinks 'others might defect, so I should defect first', everyone defects, \
                                no one gets reward (worse for all). Classic coordination game failure. Example: pool requires 80% to vote yes for upgrade, but voters \
                                can't signal intent, everyone votes no fearing others will. Missing: cheap talk phase (signaling), graduated rewards for partial \
                                cooperation, focal point mechanism. Should add pre-commitment period where participants signal non-bindingly.",
                                pc
                            ),
                            confidence: 0.81,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
