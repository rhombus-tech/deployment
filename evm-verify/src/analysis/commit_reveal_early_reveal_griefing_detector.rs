use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealEarlyRevealVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CommitRevealEarlyRevealGriefingDetector {
    bytecode: Vec<u8>,
}

impl CommitRevealEarlyRevealGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CommitRevealEarlyRevealVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_commit_phase_lock());
        vulnerabilities.extend(self.detect_reveal_before_deadline());
        vulnerabilities.extend(self.detect_no_penalty_for_early_reveal());
        vulnerabilities
    }

    fn detect_missing_commit_phase_lock(&self) -> Vec<CommitRevealEarlyRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (reveal storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let checks_commitment = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if checks_commitment {
                    let enforces_commit_deadline = self.bytecode[start..pc].iter().filter(|&&b| b == 0x42).count() >= 1;
                    if !enforces_commit_deadline {
                        vulns.push(CommitRevealEarlyRevealVulnerability {
                            pc,
                            vulnerability_type: "MissingCommitPhaseLock".to_string(),
                            description: format!("Reveal at PC {} doesn't enforce commit phase completion, allowing premature reveal. Attack: commit-reveal scheme requires all participants commit before any reveal, missing deadline allows early revealers to influence late committers, breaking randomness unpredictability. Real attack: lottery with commit-reveal, Alice commits early, Bob commits late, Alice reveals before Bob commits, Bob sees Alice's value, chooses commitment to win. Example: auction commit phase ends block 100, reveal starts block 101, Alice reveals at block 99, other bidders see her bid, adjust commitments accordingly. Missing: require(block.number > commitDeadline) before allowing reveals. Should implement: commitPhase = true until deadline, require(!commitPhase) in reveal(). Fix: add state variable commitDeadline, reject reveals before deadline, ensure all commits locked in before first reveal possible.", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_reveal_before_deadline(&self) -> Vec<CommitRevealEarlyRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (commitment verification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let verifies_hash = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                if verifies_hash {
                    let checks_timing = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                    if !checks_timing {
                        vulns.push(CommitRevealEarlyRevealVulnerability {
                            pc,
                            vulnerability_type: "RevealBeforeDeadline".to_string(),
                            description: format!("Commitment verification at PC {} allows reveal immediately after commit, breaking security model. Attack: commit-reveal security depends on all commitments finalized before reveals start, instant reveal allows later participants to see revealed values, game-theory breaks down. Real vulnerability: commit() and reveal() both callable anytime, first participant commits and immediately reveals, subsequent participants see revealed value, choose commitments to counter. Example: rock-paper-scissors game, Player1 commits 'rock', immediately reveals, Player2 commits 'paper' knowing Player1's choice, Player1 loses. Missing: reveal phase start time, minimum commit window. Should implement: revealStartTime = commitEndTime + MIN_DELAY, require(block.timestamp >= revealStartTime). Fix: enforce minimum commit period, typical pattern: commit 1-100 blocks, reveal 101-200 blocks, require block.number in correct range for each function.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_no_penalty_for_early_reveal(&self) -> Vec<CommitRevealEarlyRevealVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (commitment hash)
                let window_end = (pc + 150).min(self.bytecode.len());
                let has_reveal_function = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 2;
                if has_reveal_function {
                    let has_penalty_mechanism = self.bytecode[pc..window_end].iter().filter(|&&b| matches!(b, 0xFD | 0xF1)).count() >= 1;
                    if !has_penalty_mechanism {
                        vulns.push(CommitRevealEarlyRevealVulnerability {
                            pc,
                            vulnerability_type: "NoPenaltyForEarlyReveal".to_string(),
                            description: format!("Commit-reveal scheme at PC {} has no penalty for early reveal, enabling griefing. Attack: participant commits, reveals early breaking protocol, suffers no consequences, rational actors have no incentive to follow rules, scheme security collapses. Real attack: sealed-bid auction, bidder commits then reveals early to signal to competitors, no penalty applied, all bidders reveal early trying to coordinate, auction becomes open-bid defeating sealed mechanism. Example: commit-reveal lottery, player reveals before deadline to demonstrate they're not winner, causes others to doubt randomness fairness, griefs system without cost. Missing: slashing for early reveal, deposit forfeiture. Should implement: require deposit on commit, slash if reveal timing violated. Fix: commit requires deposit, store revealDeadline, if reveal before deadline: slash deposit, if reveal after: return deposit, economically enforce timing rules.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
