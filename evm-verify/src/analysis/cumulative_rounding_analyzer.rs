/// Cumulative Rounding Analyzer
/// Detects rounding errors that accumulate over multiple operations,
/// causing loss of funds in DeFi protocols
///
/// Famous cases: Compound rounding, dYdX precision loss, Balancer rounding exploits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CumulativeRoundingVulnerability {
    pub vulnerability_type: RoundingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub estimated_loss: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoundingIssueType {
    LoopRoundingAccumulation,      // Rounding in loops compounds loss
    ConsistentRoundingDirection,   // Always rounds same way (down/up)
    MixedPrecisionArithmetic,      // Different precision levels mixed
    DivisionBeforeMultiplication,  // Loss of precision in order
    TruncationInRewards,           // Reward calculations lose precision
    InterestRateCompounding,       // Interest calculation rounding
}

pub struct CumulativeRoundingAnalyzer {
    bytecode: Vec<u8>,
}

impl CumulativeRoundingAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CumulativeRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Division in loops (accumulating rounding)
        vulnerabilities.extend(self.detect_loop_rounding());

        // Pattern 2: Consistent rounding direction
        vulnerabilities.extend(self.detect_consistent_rounding_bias());

        // Pattern 3: Division before multiplication
        vulnerabilities.extend(self.detect_precision_loss_order());

        // Pattern 4: Reward distribution rounding
        vulnerabilities.extend(self.detect_reward_rounding_issues());

        vulnerabilities
    }

    /// Detect: Division operations inside loops
    fn detect_loop_rounding(&self) -> Vec<CumulativeRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let loops = self.find_loops();

        for (loop_start, loop_end) in loops {
            // Check if division happens in loop body
            let has_division = self.has_division_in_range(loop_start, loop_end);
            let has_accumulation = self.has_accumulation_pattern(loop_start, loop_end);

            if has_division && has_accumulation {
                vulnerabilities.push(CumulativeRoundingVulnerability {
                    vulnerability_type: RoundingIssueType::LoopRoundingAccumulation,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    description: format!(
                        "Division in loop at PC {}-{}. Rounding errors accumulate with each \
                        iteration, causing cumulative loss of funds.",
                        loop_start, loop_end
                    ),
                    exploit_scenario:
                        "Example: Distributing rewards to N users:\n\
                         for (i = 0; i < users.length; i++) {\n\
                             reward = totalReward / users.length;  // Rounds down\n\
                             transfer(users[i], reward);\n\
                         }\n\
                         Loss: (totalReward % users.length) stuck forever\n\n\
                         Real exploit: 1000 users, 999 wei each round down to 0\n\
                         Result: All rewards lost to rounding".to_string(),
                    estimated_loss:
                        "For N iterations: loss = (amount % N) * iterations\n\
                         Can accumulate to significant amounts in high-frequency operations".to_string(),
                    location: loop_start,
                });
            }
        }

        vulnerabilities
    }

    /// Detect: Always rounding in same direction (favoring protocol/user)
    fn detect_consistent_rounding_bias(&self) -> Vec<CumulativeRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for division followed by another division (chained rounding)
            if self.bytecode[pc] == 0x04 { // DIV
                // Check for another DIV nearby without ADD/SUB compensation
                if let Some(next_div) = self.find_next_opcode(pc + 1, 0x04, 50) {
                    let has_rounding_compensation = self.has_rounding_fix(pc, next_div);
                    
                    if !has_rounding_compensation {
                        vulnerabilities.push(CumulativeRoundingVulnerability {
                            vulnerability_type: RoundingIssueType::ConsistentRoundingDirection,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: format!(
                                "Chained division at PC {} and {} without rounding compensation. \
                                Consistently rounds down, favoring one party.",
                                pc, next_div
                            ),
                            exploit_scenario:
                                "Compound-style exploit:\n\
                                 exchangeRate = (cash + borrows - reserves) / totalSupply  // Rounds down\n\
                                 shares = amount / exchangeRate  // Rounds down again\n\
                                 Result: Double rounding loss, user receives fewer shares".to_string(),
                            estimated_loss:
                                "Each operation loses 0-1 wei per division.\n\
                                 Over millions of operations: significant protocol/user loss".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Division before multiplication (loses precision)
    fn detect_precision_loss_order(&self) -> Vec<CumulativeRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(20) {
            // Look for: DIV followed by MUL
            if self.bytecode[pc] == 0x04 { // DIV
                if let Some(mul_pc) = self.find_next_opcode(pc, 0x02, 20) {
                    // Check if no other DIV between them (pattern: a/b*c instead of a*c/b)
                    let has_intermediate_div = self.bytecode[pc+1..mul_pc]
                        .iter()
                        .any(|&op| op == 0x04);
                    
                    if !has_intermediate_div {
                        vulnerabilities.push(CumulativeRoundingVulnerability {
                            vulnerability_type: RoundingIssueType::DivisionBeforeMultiplication,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.75,
                            description: format!(
                                "Division before multiplication at PC {}-{}. Should reorder to \
                                multiply first to preserve precision.",
                                pc, mul_pc
                            ),
                            exploit_scenario:
                                "Bad:  result = (a / b) * c;  // Loses precision in a/b\n\
                                 Good: result = (a * c) / b;  // Preserves precision\n\n\
                                 Example: (100 / 3) * 5 = 33 * 5 = 165 ❌\n\
                                          (100 * 5) / 3 = 500 / 3 = 166 ✅\n\
                                 Lost: 1 unit per calculation".to_string(),
                            estimated_loss:
                                "Cumulative loss over many operations can be substantial.\n\
                                 Best practice: Always multiply before divide when possible".to_string(),
                            location: pc,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Reward distribution with rounding issues
    fn detect_reward_rounding_issues(&self) -> Vec<CumulativeRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for reward calculation patterns
            // Common pattern: rewardPerShare calculation
            if self.is_reward_calculation(pc) {
                let has_accumulator = self.has_dust_accumulator(pc, 200);
                let uses_high_precision = self.uses_precision_multiplier(pc, 100);
                
                if !has_accumulator && !uses_high_precision {
                    vulnerabilities.push(CumulativeRoundingVulnerability {
                        vulnerability_type: RoundingIssueType::TruncationInRewards,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: format!(
                            "Reward calculation at PC {} lacks precision multiplier or dust tracking. \
                            Small rewards may round to zero.",
                            pc
                        ),
                        exploit_scenario:
                            "Vulnerable pattern:\n\
                             rewardPerShare = totalReward / totalShares;  // Truncates\n\
                             userReward = userShares * rewardPerShare;    // User loses dust\n\n\
                             Attack: Attacker can game this by splitting holdings\n\
                             If rewardPerShare = 1.9, rounds to 1\n\
                             User with 100 shares gets 100 instead of 190".to_string(),
                        estimated_loss:
                            "Fix: Use precision multiplier (1e18)\n\
                             rewardPerShare = (totalReward * 1e18) / totalShares;\n\
                             userReward = (userShares * rewardPerShare) / 1e18;".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn find_loops(&self) -> Vec<(usize, usize)> {
        let mut loops = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(10) {
            // Look for JUMPI (conditional jump) that jumps backward
            if self.bytecode[pc] == 0x57 { // JUMPI
                // Check if this could be a loop (backward jump)
                if pc > 50 {
                    // Simple heuristic: assume loop body is ~100 bytes
                    let potential_loop_start = pc.saturating_sub(50);
                    loops.push((potential_loop_start, pc));
                }
            }

            pc += 1;
        }

        loops
    }

    fn has_division_in_range(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].contains(&0x04) // DIV
    }

    fn has_accumulation_pattern(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Look for ADD or SUB (accumulation)
        self.bytecode[start..range_end].iter()
            .any(|&op| op == 0x01 || op == 0x03) // ADD or SUB
    }

    fn find_next_opcode(&self, start: usize, opcode: u8, max_distance: usize) -> Option<usize> {
        let end = (start + max_distance).min(self.bytecode.len());
        
        self.bytecode[start..end]
            .iter()
            .position(|&op| op == opcode)
            .map(|pos| start + pos)
    }

    fn has_rounding_fix(&self, start: usize, end: usize) -> bool {
        // Look for: ADD 1 or SUB 1 (rounding compensation)
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end.saturating_sub(2) {
            if self.bytecode[i] == 0x60 && // PUSH1
               self.bytecode[i + 1] == 0x01 && // 1
               (self.bytecode[i + 2] == 0x01 || self.bytecode[i + 2] == 0x03) { // ADD or SUB
                return true;
            }
        }
        false
    }

    fn is_reward_calculation(&self, pc: usize) -> bool {
        if pc + 10 >= self.bytecode.len() {
            return false;
        }

        // Pattern: MUL followed by DIV (reward = shares * rate / divisor)
        self.bytecode[pc] == 0x02 && // MUL
        self.bytecode[pc..pc+10].contains(&0x04) // DIV nearby
    }

    fn has_dust_accumulator(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for MOD opcode (taking remainder for dust tracking)
        self.bytecode[start..end].contains(&0x06) // MOD
    }

    fn uses_precision_multiplier(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for large multiplier (1e18, 1e27, etc)
        // Pattern: PUSH with large value (>1e15)
        for i in start..end.saturating_sub(9) {
            if self.bytecode[i] == 0x6A { // PUSH11 or larger
                // Check if it's a power of 10
                let has_many_zeros = self.bytecode[i+1..i+9]
                    .iter()
                    .filter(|&&b| b == 0x00)
                    .count() >= 5;
                
                if has_many_zeros {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loop_division() {
        let bytecode = vec![
            0x57, // JUMPI (loop condition)
            0x04, // DIV (division in loop)
            0x01, // ADD (accumulation)
            0x56, // JUMP (back to start)
        ];
        
        let analyzer = CumulativeRoundingAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect loop rounding");
    }

    #[test]
    fn test_div_before_mul() {
        let bytecode = vec![
            0x04, // DIV first
            0x02, // MUL after
        ];
        
        let analyzer = CumulativeRoundingAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect division before multiplication");
    }
}
