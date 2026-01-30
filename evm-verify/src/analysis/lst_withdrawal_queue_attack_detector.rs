/// LST Withdrawal Queue Attack Detector
/// Detects vulnerabilities in Liquid Staking Token withdrawal queues (Lido, Rocket Pool, Swell)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSTWithdrawalQueueVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct LSTWithdrawalQueueAttackDetector {
    bytecode: Vec<u8>,
}

impl LSTWithdrawalQueueAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LSTWithdrawalQueueVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_queue_jump_vulnerability());
        vulnerabilities.extend(self.detect_share_price_manipulation());
        vulnerabilities.extend(self.detect_withdrawal_timing_exploit());
        vulnerabilities
    }

    fn detect_queue_jump_vulnerability(&self) -> Vec<LSTWithdrawalQueueVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_queue_operation(pc) {
                if !self.has_queue_ordering_check(pc, 150) {
                    vulnerabilities.push(LSTWithdrawalQueueVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: format!(
                            "Withdrawal queue at PC {} doesn't enforce strict ordering. \
                            Attackers can front-run legitimate withdrawals during favorable price windows.",
                            pc
                        ),
                        exploit_scenario:
                            "Queue Jump Attack:\n\
                             1. Users request withdrawals (stETH -> ETH) during normal times\n\
                             2. Withdrawal queue builds up (7-14 day wait)\n\
                             3. ETH price spikes +10% vs stETH (depeg scenario)\n\
                             4. Attacker sees profitable window\n\
                             5. Attacker submits withdrawal request with higher gas\n\
                             6. Attacker jumps queue, withdraws at favorable 1:1 rate\n\
                             7. By the time legitimate users withdraw, rate is worse\n\
                             8. Attacker profits from timing, others lose\n\n\
                             Fix:\n\
                             struct WithdrawalRequest {\n\
                                 uint256 timestamp;\n\
                                 uint256 queuePosition;\n\
                                 uint256 shares;\n\
                             }\n\
                             mapping(uint256 => WithdrawalRequest) public queue;\n\
                             uint256 public queueHead;\n\
                             \n\
                             function claimWithdrawal(uint256 requestId) {\n\
                                 require(requestId <= queueHead, 'Not ready');\n\
                                 require(block.timestamp >= queue[requestId].timestamp + MIN_DELAY);\n\
                                 // Process in order\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_share_price_manipulation(&self) -> Vec<LSTWithdrawalQueueVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_withdrawal_calculation(pc) {
                if !self.has_share_price_bounds_check(pc, 100) {
                    vulnerabilities.push(LSTWithdrawalQueueVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Withdrawal calculation at PC {} uses unbounded share price. \
                            During rebases or validator slashing, share price can be manipulated.",
                            pc
                        ),
                        exploit_scenario:
                            "Share Price Manipulation During Withdrawal:\n\
                             1. stETH rebases daily based on validator rewards\n\
                             2. User requests withdrawal of 100 stETH\n\
                             3. During unbonding period, negative rebase occurs (slashing)\n\
                             4. Share price: 1 stETH = 0.95 ETH\n\
                             5. User receives 95 ETH instead of 100 ETH\n\
                             6. If withdrawal rate not locked at request time, user loses 5 ETH\n\
                             7. Attacker can trigger this by timing validator exits\n\n\
                             Lido-style fix:\n\
                             function requestWithdrawal(uint256 shares) returns (uint256 requestId) {\n\
                                 uint256 ethAmount = shares * getCurrentRate() / 1e18;\n\
                                 requests[requestId] = WithdrawalRequest({\n\
                                     shares: shares,\n\
                                     ethAmount: ethAmount,  // Lock rate at request time!\n\
                                     timestamp: block.timestamp\n\
                                 });\n\
                             }\n\
                             \n\
                             function claimWithdrawal(uint256 requestId) {\n\
                                 // Use locked ethAmount, not recalculated\n\
                                 ETH.transfer(msg.sender, requests[requestId].ethAmount);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_withdrawal_timing_exploit(&self) -> Vec<LSTWithdrawalQueueVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_withdrawal_claim(pc) {
                if !self.has_timing_delay_check(pc, 120) {
                    vulnerabilities.push(LSTWithdrawalQueueVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Withdrawal claim at PC {} doesn't enforce minimum delay. \
                            Attackers can request and immediately claim during oracle lag windows.",
                            pc
                        ),
                        exploit_scenario:
                            "Instant Withdrawal Timing Attack:\n\
                             1. Oracle updates ETH/stETH rate every 24 hours\n\
                             2. ETH price increases 5% on exchanges\n\
                             3. Oracle hasn't updated yet (lag window)\n\
                             4. Attacker requests withdrawal at old rate\n\
                             5. If no delay enforced, attacker claims immediately\n\
                             6. Attacker gets ETH at old (favorable) rate\n\
                             7. Oracle updates, rate adjusts\n\
                             8. Attacker profits from the lag\n\n\
                             Fix:\n\
                             uint256 constant MIN_WITHDRAWAL_DELAY = 7 days;\n\
                             \n\
                             function claimWithdrawal(uint256 requestId) {\n\
                                 WithdrawalRequest memory req = requests[requestId];\n\
                                 require(\n\
                                     block.timestamp >= req.timestamp + MIN_WITHDRAWAL_DELAY,\n\
                                     'Withdrawal not ready'\n\
                                 );\n\
                                 // Claim logic\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_queue_operation(&self, pc: usize) -> bool {
        if pc + 80 >= self.bytecode.len() { return false; }
        let mut has_push = false;
        let mut has_sstore = false;
        for i in pc..(pc + 80).min(self.bytecode.len()) {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f { has_push = true; }
            if self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        has_push && has_sstore
    }

    fn has_queue_ordering_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end.saturating_sub(5) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {  // LT or GT
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd { return true; }  // REVERT
                }
            }
        }
        false
    }

    fn is_withdrawal_calculation(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() { return false; }
        let mut has_mul = false;
        let mut has_div = false;
        for i in pc..(pc + 50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x02 { has_mul = true; }
            if self.bytecode[i] == 0x04 { has_div = true; }
        }
        has_mul && has_div
    }

    fn has_share_price_bounds_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x12 | 0x13) {
                return true;
            }
        }
        false
    }

    fn is_withdrawal_claim(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf0 {  // CALL or CREATE
                return true;
            }
        }
        false
    }

    fn has_timing_delay_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                for j in (i + 1)..(i + 15).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) {  // LT or GT
                        return true;
                    }
                }
            }
        }
        false
    }
}
