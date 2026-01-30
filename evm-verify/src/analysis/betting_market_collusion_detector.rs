use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BettingCollusionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BettingMarketCollusionDetector {
    bytecode: Vec<u8>,
}

impl BettingMarketCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BettingCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_peer_to_peer_match_fixing());
        vulnerabilities.extend(self.detect_liquidity_pool_manipulation());
        vulnerabilities.extend(self.detect_sybil_betting_attack());

        vulnerabilities
    }

    fn detect_peer_to_peer_match_fixing(&self) -> Vec<BettingCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (bet matching)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_bet_matching = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOADs
                let has_counterparty = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_bet_matching {
                    let has_reputation_system = window.iter().any(|&b| b == 0x20); // KECCAK256 (user hash)
                    let has_stake_requirement = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_reputation_system && !has_stake_requirement {
                        vulns.push(BettingCollusionVulnerability {
                            pc,
                            vulnerability_type: "PeerToPeerMatchFixing".to_string(),
                            description: format!(
                                "P2P betting at PC {} vulnerable to collusion and match fixing. Attack: two colluding users create market with insider knowledge, user A \
                                knows event outcome (sports match fix, rigged outcome), creates market offering generous odds, user B (accomplice) bets heavily on certain \
                                outcome, outcome occurs as planned, profit split between colluders. Other users may bet on wrong side unaware of fix. Missing: reputation \
                                system for market creators, minimum stake/skin-in-game requirements, pattern detection for suspicious betting, oracle verification of event \
                                legitimacy. Should implement: creator stake slashed if market disputed, require market creators to have established on-chain reputation.",
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

    fn detect_liquidity_pool_manipulation(&self) -> Vec<BettingCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (odds calculation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pool_ratio = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                let has_bet_placement = window.iter().any(|&b| b == 0x01); // ADD
                
                if has_pool_ratio {
                    let has_max_bet_size = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_volume_limits = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 4;
                    
                    if !has_max_bet_size {
                        vulns.push(BettingCollusionVulnerability {
                            pc,
                            vulnerability_type: "LiquidityPoolManipulation".to_string(),
                            description: format!(
                                "Betting pool odds at PC {} vulnerable to manipulation via large bets. Attack: automated market maker adjusts odds based on pool ratio, \
                                attacker with insider information places massive bet skewing odds, other users see skewed odds and follow (herd behavior), attacker knows \
                                real outcome and profits. Example: prediction market on election, insider bets $10M on candidate A, odds shift dramatically, uninformed \
                                users assume insider knowledge and follow, candidate A loses, attacker collects from follower bets. Missing: maximum bet size relative to \
                                pool, progressive fees for large bets, bet size caps per user. Should implement: max single bet = 5% of pool TVL.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_sybil_betting_attack(&self) -> Vec<BettingCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (reward calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_participation_reward = window.iter().any(|&b| b == 0x01); // ADD
                let has_user_tracking = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_participation_reward {
                    let has_sybil_resistance = window.iter().any(|&b| b == 0x20); // KECCAK256 (identity)
                    let has_staking_requirement = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_sybil_resistance && !has_staking_requirement {
                        vulns.push(BettingCollusionVulnerability {
                            pc,
                            vulnerability_type: "SybilBettingAttack".to_string(),
                            description: format!(
                                "Betting reward distribution at PC {} vulnerable to Sybil attack. Attack: protocol distributes rewards/tokens to betting participants, \
                                attacker creates many addresses (Sybil identities), places minimum bets from each, collects participation rewards, cost = N * min_bet, \
                                reward = N * participation_bonus. If bonus > bet, profitable. Example: protocol airdrops tokens to first 10,000 bettors, attacker creates \
                                10,000 addresses with $1 bets each, receives $50,000 in tokens. Missing: proof of unique humanity, stake requirements, address clustering \
                                detection. Should require: meaningful stake (e.g., $100 minimum), or use Gitcoin Passport / Worldcoin for Sybil resistance.",
                                pc
                            ),
                            confidence: 0.86,
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
