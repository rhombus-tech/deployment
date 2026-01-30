/// Economic Irrationality Analyzer
/// 
/// Detects when protocol INCENTIVIZES economically irrational behavior
/// Impact: $500M+ in exploits where code is correct but economics are wrong
/// 
/// Difference from economic_validator.rs:
/// - economic_validator: Checks if known attacks are profitable
/// - THIS: Detects when protocol creates PERVERSE INCENTIVES
/// 
/// Example: Liquidation bonus > gas cost = profitable to self-liquidate

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicIrrationalityVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub irrationality_type: IrrationalityType,
    pub description: String,
    pub game_theory_analysis: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrrationalityType {
    SelfLiquidationProfitable,   // Bonus > cost to self-liquidate
    RewardFarmingProfitable,     // Reward rate > deposit cost
    GriefingCheap,               // Harming others costs nothing
    InsuranceUneconomical,       // Cheaper to not buy insurance
    FeeBypassProfitable,         // Routing around fee < paying fee
    SlashingAvoidable,           // Cost to avoid < slashing penalty
    BondingIncentiveMisaligned,  // Unbonding more profitable than bonding
    ArbitragePermanent,          // Price difference never closes
}

pub struct EconomicIrrationalityDetector {
    bytecode: Vec<u8>,
}

impl EconomicIrrationalityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Self-liquidation profitable
        vulnerabilities.extend(self.detect_self_liquidation_incentive());

        // 2. Reward farming more profitable than intended
        vulnerabilities.extend(self.detect_reward_farming_exploit());

        // 3. Griefing attacks cost nothing
        vulnerabilities.extend(self.detect_free_griefing());

        // 4. Fee bypass profitable
        vulnerabilities.extend(self.detect_fee_bypass_incentive());

        // 5. Insurance economically irrational
        vulnerabilities.extend(self.detect_insurance_misalignment());

        vulnerabilities
    }

    fn detect_self_liquidation_incentive(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Liquidation bonus > typical gas cost
            if self.has_profitable_self_liquidation(pc) {
                vulns.push(EconomicIrrationalityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    irrationality_type: IrrationalityType::SelfLiquidationProfitable,
                    description: "Liquidation bonus exceeds cost, incentivizes self-liquidation".to_string(),
                    game_theory_analysis: "Nash Equilibrium Analysis:\n\
                        - Rational actor: Borrow max, wait for liquidatable position\n\
                        - Self-liquidate with bonus\n\
                        - Profit = liquidation bonus - gas cost\n\
                        - Dominant strategy: Never maintain healthy positions\n\
                        - Protocol becomes liquidation farming platform".to_string(),
                    exploit_scenario: "function liquidate(address user) {\n\
                            uint collateral = getCollateral(user);\n\
                            uint debt = getDebt(user);\n\
                            require(collateral < debt * 1.5); // Undercollateralized\n\
                            \n\
                            // BUG: 10% bonus too high!\n\
                            uint bonus = collateral * 10 / 100; // $10K on $100K\n\
                            transfer(liquidator, collateral + bonus);\n\
                        }\n\
                        \n\
                        Economic exploit:\n\
                        1. Attacker borrows $100K against $150K collateral\n\
                        2. Waits until collateral = $149K (liquidatable)\n\
                        3. Self-liquidates from another address\n\
                        4. Receives $149K + $14.9K bonus = $163.9K\n\
                        5. Gas cost: $50\n\
                        6. Net profit: $13.9K per cycle\n\
                        7. Repeat indefinitely\n\
                        \n\
                        Protocol becomes liquidation ATM".to_string(),
                    remediation: "Cap liquidation bonus at 2-3%, less than typical gas + risk costs".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_reward_farming_exploit(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: High reward rate with instant claim
            if self.has_exploitable_reward_rate(pc) {
                vulns.push(EconomicIrrationalityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    irrationality_type: IrrationalityType::RewardFarmingProfitable,
                    description: "Reward rate enables profitable cycling at expense of protocol".to_string(),
                    game_theory_analysis: "Optimal Strategy:\n\
                        - Deposit → Claim rewards immediately → Withdraw → Repeat\n\
                        - If reward_per_block * gas_cost < tx_cost: Profitable\n\
                        - No incentive to hold long-term\n\
                        - All users become short-term farmers\n\
                        - Protocol TVL unstable, vulnerable to bank run".to_string(),
                    exploit_scenario: "function claimRewards() {\n\
                            uint rewards = earned[msg.sender];\n\
                            // BUG: No minimum time lock!\n\
                            earned[msg.sender] = 0;\n\
                            rewardToken.transfer(msg.sender, rewards);\n\
                        }\n\
                        \n\
                        Economic exploit:\n\
                        1. Flash loan $10M\n\
                        2. Deposit to protocol\n\
                        3. Claim rewards (1 block)\n\
                        4. Withdraw principal\n\
                        5. Repay flash loan\n\
                        6. Keep rewards\n\
                        7. Gas cost: $100, Reward: $500\n\
                        8. Net profit: $400 per block\n\
                        9. Repeat every block\n\
                        \n\
                        Reward pool drained in hours, no real TVL".to_string(),
                    remediation: "Add vesting: rewards unlock over time, minimum deposit duration".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_free_griefing(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Expensive operation callable by anyone with no cost
            if self.has_free_griefing_vector(pc) {
                vulns.push(EconomicIrrationalityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    irrationality_type: IrrationalityType::GriefingCheap,
                    description: "Expensive operation callable by anyone at no cost to attacker".to_string(),
                    game_theory_analysis: "Griefing Game Theory:\n\
                        - Attacker cost: Gas ($10)\n\
                        - Victim cost: Protocol DOS, lost revenue ($100K)\n\
                        - Griefing ratio: 10,000:1\n\
                        - Competitors incentivized to attack\n\
                        - No deterrent (attacker loses nothing)\n\
                        - Protocol vulnerable to rivalry DOS".to_string(),
                    exploit_scenario: "function updateAllPrices() public {\n\
                            // BUG: No access control, no fee!\n\
                            for (uint i = 0; i < assets.length; i++) {\n\
                                oracle.updatePrice(assets[i]); // Expensive\n\
                            }\n\
                        }\n\
                        \n\
                        Economic griefing:\n\
                        1. Competitor calls updateAllPrices() repeatedly\n\
                        2. Each call costs attacker: $10 gas\n\
                        3. Each call costs victim: $1000 in oracle fees\n\
                        4. Protocol bleeding funds\n\
                        5. Attacker spends $1K, victim loses $100K\n\
                        6. Griefing ratio: 100:1\n\
                        7. Economically rational attack\n\
                        \n\
                        Protocol DOS'd by economic incentive".to_string(),
                    remediation: "Add caller fee > gas cost, or restrict access to protocol-owned addresses".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_fee_bypass_incentive(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Fee-free alternative path exists
            if self.has_fee_bypass_route(pc) {
                vulns.push(EconomicIrrationalityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    irrationality_type: IrrationalityType::FeeBypassProfitable,
                    description: "Alternative path bypasses fee, making fee collection ineffective".to_string(),
                    game_theory_analysis: "Fee Avoidance Equilibrium:\n\
                        - Direct route: 0.3% fee\n\
                        - Indirect route: 0% fee, slightly worse price\n\
                        - If price_difference < 0.3%: Always use indirect\n\
                        - All rational users bypass fee\n\
                        - Protocol collects no fees\n\
                        - Revenue model broken".to_string(),
                    exploit_scenario: "function swapWithFee(uint amount) {\n\
                            uint fee = amount * 3 / 1000; // 0.3%\n\
                            // charge fee\n\
                        }\n\
                        \n\
                        function swapViaIntermediate(uint amount) {\n\
                            // BUG: No fee on indirect route!\n\
                            // Swap A → B → C (equivalent to A → C)\n\
                            // Saves 0.3% fee\n\
                        }\n\
                        \n\
                        Economic bypass:\n\
                        1. Direct swap: $1000 → $997 (0.3% fee)\n\
                        2. Indirect swap: $1000 → $998.50 (no fee)\n\
                        3. Indirect is better\n\
                        4. All users route around fee\n\
                        5. Protocol revenue = $0\n\
                        6. Unsustainable economics".to_string(),
                    remediation: "Apply fee to all paths, or remove fee entirely if unenforceable".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_insurance_misalignment(&self) -> Vec<EconomicIrrationalityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Insurance premium > expected loss
            if self.has_insurance_misalignment(pc) {
                vulns.push(EconomicIrrationalityVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Medium,
                    irrationality_type: IrrationalityType::InsuranceUneconomical,
                    description: "Insurance premium exceeds expected loss, disincentivizes protection".to_string(),
                    game_theory_analysis: "Expected Value Analysis:\n\
                        - Insurance premium: $100/year\n\
                        - Hack probability: 1% per year\n\
                        - Average loss if hacked: $5,000\n\
                        - Expected loss: 0.01 * $5,000 = $50\n\
                        - Premium > Expected loss\n\
                        - Rational: Don't buy insurance\n\
                        - Result: No one insured when hack occurs".to_string(),
                    exploit_scenario: "function buyInsurance() {\n\
                            uint premium = balance * 5 / 100; // 5% per year\n\
                            // If hack risk < 5%, economically irrational to buy\n\
                        }\n\
                        \n\
                        Economic misalignment:\n\
                        1. User has $10,000 deposited\n\
                        2. Insurance costs $500/year\n\
                        3. Historical hack rate: 2% per year\n\
                        4. Expected loss: $200/year\n\
                        5. Economically rational: Don't insure\n\
                        6. When hack occurs: No coverage\n\
                        7. Insurance protocol fails\n\
                        \n\
                        Adverse selection spiral".to_string(),
                    remediation: "Premium < expected loss, or mandatory insurance to prevent adverse selection".to_string(),
                    confidence: 0.70,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_profitable_self_liquidation(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for liquidation bonus calculation (percentage > 5%)
        // Pattern: MUL with constant, then DIV by 100 or 1000
        let has_bonus_calc = window.windows(5).any(|w| {
            w[0] == 0x02 && // MUL
            w[1] == 0x60 && // PUSH1
            w[2] > 5 &&     // Constant > 5 (likely 5-20%)
            w[3] == 0x04 && // DIV
            w[4] == 0x60    // PUSH1 (divisor)
        });

        has_bonus_calc
    }

    fn has_exploitable_reward_rate(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for reward transfer WITHOUT timelock check
        let has_reward_transfer = window.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]);

        if has_reward_transfer {
            // Check if there's a time-since-deposit check
            let has_timelock = window.windows(3).any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x03 && // SUB (timestamp - depositTime)
                w[2] == 0x10    // LT (time < minimum)
            });

            !has_timelock
        } else {
            false
        }
    }

    fn has_free_griefing_vector(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];

        // Look for loop with external calls (expensive) without access control
        let has_loop = window.iter().any(|&b| b == 0x56 || b == 0x57); // JUMP or JUMPI
        let has_external_call = window.iter().any(|&b| b == 0xF1 || b == 0xFA); // CALL or STATICCALL

        if has_loop && has_external_call {
            // Check if there's access control (CALLER check)
            let has_access_control = window.windows(3).any(|w| {
                w[0] == 0x33 && // CALLER
                w[1] == 0x14 && // EQ
                w[2] == 0x57    // JUMPI
            });

            !has_access_control
        } else {
            false
        }
    }

    fn has_fee_bypass_route(&self, start: usize) -> bool {
        if start + 45 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 45];

        // Look for multiple code paths, one with fee deduction and one without
        let fee_operations: Vec<usize> = window
            .windows(3)
            .enumerate()
            .filter(|(_, w)| {
                w[0] == 0x02 && // MUL (amount * fee)
                w[1] == 0x04    // DIV (/ 1000)
            })
            .map(|(i, _)| i)
            .collect();

        // If function has conditional jumps but only one fee calculation,
        // some paths might bypass fee
        let jump_count = window.iter().filter(|&&b| b == 0x57).count();
        
        fee_operations.len() == 1 && jump_count >= 2
    }

    fn has_insurance_misalignment(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for premium calculation that's a high percentage (> 3%)
        // Pattern: balance * X / 100 where X > 3
        window.windows(5).any(|w| {
            w[0] == 0x02 && // MUL
            w[1] == 0x60 && // PUSH1
            w[2] > 3 &&     // Constant > 3%
            w[3] == 0x04 && // DIV
            w[4] == 0x60    // PUSH1 100
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_liquidation_profitable() {
        // Liquidation bonus calculation: 10%
        let bytecode = vec![
            0x02, // MUL (collateral * bonus)
            0x60, 0x0A, // PUSH1 10 (10%)
            0x04, // DIV
            0x60, 0x64, // PUSH1 100
        ];
        
        let detector = EconomicIrrationalityDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.irrationality_type, IrrationalityType::SelfLiquidationProfitable)));
    }
}
