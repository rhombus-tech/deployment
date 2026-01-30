/// Bad Debt Socialization Detector
/// Detects improper bad debt distribution in lending protocols

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadDebtSocializationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct BadDebtSocializationDetector {
    bytecode: Vec<u8>,
}

impl BadDebtSocializationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BadDebtSocializationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unprotected_bad_debt_distribution());
        vulnerabilities.extend(self.detect_unfair_loss_allocation());
        vulnerabilities.extend(self.detect_protocol_reserves_bypass());
        vulnerabilities
    }

    fn detect_unprotected_bad_debt_distribution(&self) -> Vec<BadDebtSocializationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_liquidation_with_shortfall(pc) {
                if !self.has_bad_debt_handling(pc, 200) {
                    vulnerabilities.push(BadDebtSocializationVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: format!(
                            "Liquidation at PC {} doesn't handle bad debt properly. \
                            Shortfalls get socialized to all lenders without protection.",
                            pc
                        ),
                        exploit_scenario:
                            "Bad Debt Socialization Attack:\n\
                             1. User borrows $1M with $1.1M collateral (110% ratio)\n\
                             2. Collateral crashes -50% → now worth $550K\n\
                             3. Liquidator should repay $1M debt, get $550K collateral\n\
                             4. Liquidation executes but only recovers $550K\n\
                             5. Protocol has $450K bad debt (shortfall)\n\
                             6. If no reserves, this loss is socialized to all lenders\n\
                             7. Every lender's balance decreases proportionally\n\
                             8. Attacker can intentionally create bad debt via price manipulation\n\n\
                             Mango Markets exploit ($110M) used similar mechanism\n\n\
                             Fix:\n\
                             function liquidate(address user) {\n\
                                 uint256 debt = borrowBalance[user];\n\
                                 uint256 collateral = collateralBalance[user];\n\
                                 \n\
                                 uint256 recovered = min(debt, collateral);\n\
                                 uint256 shortfall = debt - recovered;\n\
                                 \n\
                                 if (shortfall > 0) {\n\
                                     // 1. Try protocol reserves first\n\
                                     uint256 fromReserves = min(shortfall, protocolReserves);\n\
                                     protocolReserves -= fromReserves;\n\
                                     shortfall -= fromReserves;\n\
                                     \n\
                                     // 2. Only socialize remaining after reserves\n\
                                     if (shortfall > 0) {\n\
                                         badDebt += shortfall;\n\
                                         emit BadDebtSocialized(shortfall);\n\
                                         // Pause new borrows until resolved\n\
                                         borrowingPaused = true;\n\
                                     }\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_unfair_loss_allocation(&self) -> Vec<BadDebtSocializationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_bad_debt_distribution(pc) {
                if !self.has_fair_allocation_logic(pc, 180) {
                    vulnerabilities.push(BadDebtSocializationVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Bad debt distribution at PC {} doesn't allocate losses fairly. \
                            Some users may bear disproportionate losses.",
                            pc
                        ),
                        exploit_scenario:
                            "Unfair Loss Allocation:\n\
                             1. Protocol has $100M in deposits, $10M bad debt\n\
                             2. User A deposited 1 year ago: $50M\n\
                             3. User B deposited yesterday: $50M\n\
                             4. Bad debt gets split equally: each loses $5M\n\
                             5. User A: 10% loss on long-term deposit\n\
                             6. User B: 10% loss but was only exposed 1 day\n\
                             7. User B effectively had higher risk-adjusted loss\n\
                             8. Attackers can exploit by depositing right before loss socialization\n\n\
                             Better approach (time-weighted):\n\
                             struct Deposit {\n\
                                 uint256 amount;\n\
                                 uint256 timestamp;\n\
                                 uint256 cumulativeLossIndex;\n\
                             }\n\
                             \n\
                             function socializeBadDebt(uint256 loss) {\n\
                                 // Distribute based on time-weighted exposure\n\
                                 uint256 totalTimeWeighted = 0;\n\
                                 \n\
                                 for (user : users) {\n\
                                     uint256 timeExposed = block.timestamp - deposits[user].timestamp;\n\
                                     totalTimeWeighted += deposits[user].amount * timeExposed;\n\
                                 }\n\
                                 \n\
                                 for (user : users) {\n\
                                     uint256 timeExposed = block.timestamp - deposits[user].timestamp;\n\
                                     uint256 userWeight = (deposits[user].amount * timeExposed) / totalTimeWeighted;\n\
                                     uint256 userLoss = loss * userWeight;\n\
                                     deposits[user].amount -= userLoss;\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_protocol_reserves_bypass(&self) -> Vec<BadDebtSocializationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_bad_debt_distribution(pc) {
                if !self.checks_protocol_reserves_first(pc, 150) {
                    vulnerabilities.push(BadDebtSocializationVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Bad debt handling at PC {} doesn't use protocol reserves first. \
                            Socializes losses to users before depleting reserves.",
                            pc
                        ),
                        exploit_scenario:
                            "Protocol Reserves Bypass:\n\
                             1. Protocol has $5M in reserves (for bad debt coverage)\n\
                             2. Bad debt event: $3M shortfall\n\
                             3. Instead of using reserves, directly socializes to users\n\
                             4. All lenders lose pro-rata share of $3M\n\
                             5. Protocol reserves sit unused\n\
                             6. This defeats the purpose of maintaining reserves\n\n\
                             Correct priority:\n\
                             function handleBadDebt(uint256 shortfall) {\n\
                                 uint256 remaining = shortfall;\n\
                                 \n\
                                 // 1. Protocol reserves (first line of defense)\n\
                                 if (protocolReserves > 0) {\n\
                                     uint256 fromReserves = min(remaining, protocolReserves);\n\
                                     protocolReserves -= fromReserves;\n\
                                     remaining -= fromReserves;\n\
                                 }\n\
                                 \n\
                                 // 2. Insurance fund (if available)\n\
                                 if (remaining > 0 && insuranceFund > 0) {\n\
                                     uint256 fromInsurance = min(remaining, insuranceFund);\n\
                                     insuranceFund -= fromInsurance;\n\
                                     remaining -= fromInsurance;\n\
                                 }\n\
                                 \n\
                                 // 3. Only socialize as last resort\n\
                                 if (remaining > 0) {\n\
                                     socializeToLenders(remaining);\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_liquidation_with_shortfall(&self, pc: usize) -> bool {
        if pc + 150 >= self.bytecode.len() { return false; }
        
        let mut has_liquidation = false;
        let mut has_arithmetic = false;
        
        for i in pc..(pc + 150).min(self.bytecode.len()) {
            // Look for external call (liquidation trigger)
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                has_liquidation = true;
            }
            // Look for SUB (debt - collateral = shortfall)
            if self.bytecode[i] == 0x03 {
                has_arithmetic = true;
            }
        }
        
        has_liquidation && has_arithmetic
    }

    fn has_bad_debt_handling(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        
        // Look for conditional logic handling shortfall
        for i in pc..end {
            if self.bytecode[i] == 0x11 { // GT (checking if shortfall > 0)
                for j in (i + 1)..(i + 20).min(end) {
                    if self.bytecode[j] == 0x57 { // JUMPI (conditional branch)
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_bad_debt_distribution(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        
        // Look for loop-like pattern (iterating over users)
        let mut has_loop = false;
        let mut has_division = false;
        
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 { // JUMP or JUMPI
                has_loop = true;
            }
            if self.bytecode[i] == 0x04 { // DIV (pro-rata calculation)
                has_division = true;
            }
        }
        
        has_loop && has_division
    }

    fn has_fair_allocation_logic(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for time-based calculations (TIMESTAMP usage)
        for i in start..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn checks_protocol_reserves_first(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range);
        
        // Look for SLOAD of reserves before distribution
        let mut found_reserve_load = false;
        let mut found_comparison = false;
        
        for i in start..pc {
            if self.bytecode[i] == 0x54 { // SLOAD
                found_reserve_load = true;
            }
            if found_reserve_load && self.bytecode[i] == 0x11 { // GT
                found_comparison = true;
            }
        }
        
        found_reserve_load && found_comparison
    }
}
