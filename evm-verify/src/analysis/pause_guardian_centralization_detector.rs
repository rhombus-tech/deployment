use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseGuardianCentralizationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PauseGuardianCentralizationDetector {
    bytecode: Vec<u8>,
}

impl PauseGuardianCentralizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PauseGuardianCentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_single_pause_authority());
        vulnerabilities.extend(self.detect_permanent_pause_risk());
        vulnerabilities.extend(self.detect_pause_without_unpause());
        vulnerabilities
    }

    fn detect_single_pause_authority(&self) -> Vec<PauseGuardianCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (pause state update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let checks_caller = self.bytecode[start..pc].iter().filter(|&&b| b == 0x33).count() >= 1;
                if checks_caller {
                    let checks_multiple_guardians = self.bytecode[start..pc].iter().filter(|&&b| b == 0x14).count() >= 2;
                    if !checks_multiple_guardians {
                        vulns.push(PauseGuardianCentralizationVulnerability {
                            pc, vulnerability_type: "SinglePauseAuthority".to_string(),
                            description: format!("Pause mechanism at PC {} controlled by single address, creating centralization risk. Attack: single guardian address compromised, attacker pauses protocol indefinitely, all user funds locked, protocol DoS'd until governance intervention. Real vulnerability: Compound-style pause guardian with single EOA, private key leaked, attacker calls _setPaused(true), all borrows/repayments/liquidations frozen, users can't access funds. Example: protocol has pause() restricted to guardian address, guardian wallet compromised via phishing, attacker pauses, $100M locked, governance timelock requires 7 days to change guardian, funds inaccessible for week. Missing: multi-sig guardian, timelock on pause, decentralized pause mechanism. Should implement: guardian = MultiSigWallet, or require M-of-N signatures to pause. Fix: use multi-sig guardian (3-of-5), implement automatic unpause after N blocks, add community override mechanism for malicious pause.", pc),
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

    fn detect_permanent_pause_risk(&self) -> Vec<PauseGuardianCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (pause flag set)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let sets_pause_true = self.bytecode[start..pc].iter().filter(|&&b| b == 0x60).any(|_| true);
                if sets_pause_true {
                    let window_end = (pc + 150).min(self.bytecode.len());
                    let has_auto_unpause = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x42).count() >= 1;
                    if !has_auto_unpause {
                        vulns.push(PauseGuardianCentralizationVulnerability {
                            pc, vulnerability_type: "PermanentPauseRisk".to_string(),
                            description: format!("Pause mechanism at PC {} lacks automatic unpause, risking permanent protocol freeze. Attack: guardian pauses protocol due to perceived threat, guardian address becomes inaccessible (lost key, guardian exits project), paused state permanent, all funds locked forever. Real scenario: DeFi protocol pauses during market crash, guardian sets paused=true, guardian key lost in custody incident, no backup guardian, protocol frozen permanently, $50M locked indefinitely. Example: protocol pauses during hack investigation, guardian EOA key stored on compromised laptop, laptop destroyed, no unpause function callable by governance, funds unrecoverable. Missing: automatic unpause timer, backup unpause mechanism, governance override. Should implement: pausedUntil = block.timestamp + MAX_PAUSE_DURATION, auto-unpause after threshold. Fix: add pauseUntil timestamp, check block.timestamp > pauseUntil returns false for paused(), allow governance to override pause with timelock, implement emergency unpause via DAO vote.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_pause_without_unpause(&self) -> Vec<PauseGuardianCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_pause_function = false;
        let mut has_unpause_function = false;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x60 && pc + 1 < self.bytecode.len() {
                if self.bytecode[pc + 1] == 0x01 {
                    let window_end = (pc + 50).min(self.bytecode.len());
                    if self.bytecode[pc..window_end].iter().any(|&b| b == 0x55) {
                        has_pause_function = true;
                    }
                }
                if self.bytecode[pc + 1] == 0x00 {
                    let window_end = (pc + 50).min(self.bytecode.len());
                    if self.bytecode[pc..window_end].iter().any(|&b| b == 0x55) {
                        has_unpause_function = true;
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        
        if has_pause_function && !has_unpause_function {
            vulns.push(PauseGuardianCentralizationVulnerability {
                pc: 0, vulnerability_type: "PauseWithoutUnpause".to_string(),
                description: format!("Contract has pause() function but no corresponding unpause(), creating unrecoverable pause state. Attack: guardian or malicious actor calls pause(), contract permanently frozen as no unpause mechanism exists, all funds and functionality locked forever. Real vulnerability: Pausable contract implements _pause() internal function, exposes pause() publicly, but unpause() either nonexistent or permanently restricted. Example: contract inherits OpenZeppelin Pausable, implements pause() as onlyOwner, but doesn't implement unpause(), owner pauses during incident, realizes no way to resume, protocol permanently dead. Missing: unpause function, or time-bound pause. Should implement: function unpause() public onlyOwner {{ _unpause(); }}. Fix: ensure every pause mechanism has corresponding unpause accessible to governance, implement automatic unpause after time threshold, add circuit breaker auto-resume after N blocks."),
                confidence: 0.88,
            });
        }
        
        vulns
    }
}
