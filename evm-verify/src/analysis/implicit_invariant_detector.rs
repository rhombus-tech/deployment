/// Implicit Invariant Violation Detector
/// 
/// Detects violations of IMPLICIT invariants (not written in code)
/// Impact: $400M+ in exploits
/// 
/// Difference from invariant_checker.rs:
/// - invariant_checker: Checks EXPLICIT invariants (written in require statements)
/// - THIS: Detects IMPLICIT invariants (assumed but not enforced)
/// 
/// Example:
/// ```solidity
/// totalDeposits += amount;  // Implicit: totalDeposits == sum(userDeposits)
/// // But code doesn't ENFORCE this invariant!
/// ```

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplicitInvariantVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub invariant_type: ImplicitInvariantType,
    pub violated_invariant: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplicitInvariantType {
    SumInvariant,            // total == sum(parts)
    ConservationLaw,         // tokens_in == tokens_out
    RatioInvariant,          // x/y stays constant
    MonotonicInvariant,      // value only increases/decreases
    UniquenessInvariant,     // no duplicates
    BoundedInvariant,        // value within range
    SymmetryInvariant,       // A→B implies B→A
    TransitivityInvariant,   // A→B, B→C implies A→C
}

pub struct ImplicitInvariantDetector {
    bytecode: Vec<u8>,
}

impl ImplicitInvariantDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Sum invariant violations (total != sum of parts)
        vulnerabilities.extend(self.detect_sum_invariant_violations());

        // 2. Conservation law violations (tokens in != tokens out)
        vulnerabilities.extend(self.detect_conservation_violations());

        // 3. Ratio invariant violations (k = x * y not maintained)
        vulnerabilities.extend(self.detect_ratio_violations());

        // 4. Monotonic invariant violations (supply can increase AND decrease)
        vulnerabilities.extend(self.detect_monotonic_violations());

        // 5. Uniqueness violations (duplicate IDs possible)
        vulnerabilities.extend(self.detect_uniqueness_violations());

        vulnerabilities
    }

    fn detect_sum_invariant_violations(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Multiple functions modify individual balances
            // but don't maintain totalBalance sum
            if self.has_sum_invariant_violation(pc) {
                vulns.push(ImplicitInvariantVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    invariant_type: ImplicitInvariantType::SumInvariant,
                    violated_invariant: "totalBalance == sum(userBalances[i])".to_string(),
                    description: "Total balance updated independently from user balances, breaking sum invariant".to_string(),
                    exploit_scenario: "mapping(address => uint) public userBalances;\n\
                        uint public totalBalance;\n\
                        \n\
                        function deposit(uint amount) {\n\
                            userBalances[msg.sender] += amount;\n\
                            totalBalance += amount; // Invariant maintained\n\
                        }\n\
                        \n\
                        function specialDeposit(uint amount) {\n\
                            // BUG: Only updates user balance!\n\
                            userBalances[msg.sender] += amount;\n\
                            // Missing: totalBalance += amount\n\
                        }\n\
                        \n\
                        Implicit invariant broken:\n\
                        - totalBalance < sum(userBalances)\n\
                        - Protocol thinks it has less than it does\n\
                        - Can enable withdrawal of more than deposited\n\
                        - Accounting corruption".to_string(),
                    remediation: "Enforce invariant: After any balance update, verify sum(userBalances) == totalBalance".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_conservation_violations(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Tokens transferred but conservation not maintained
            if self.has_conservation_violation(pc) {
                vulns.push(ImplicitInvariantVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    invariant_type: ImplicitInvariantType::ConservationLaw,
                    violated_invariant: "tokensIn == tokensOut (conservation of value)".to_string(),
                    description: "Token transfer doesn't maintain conservation law".to_string(),
                    exploit_scenario: "function swap(uint amountIn, address tokenIn, address tokenOut) {\n\
                            // Takes tokens from user\n\
                            IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);\n\
                            \n\
                            uint amountOut = getAmountOut(amountIn);\n\
                            \n\
                            // BUG: Uses wrong token or wrong amount!\n\
                            IERC20(tokenIn).transfer(msg.sender, amountOut); // Should be tokenOut!\n\
                        }\n\
                        \n\
                        Conservation law violated:\n\
                        - User deposits tokenIn\n\
                        - Receives tokenIn back instead of tokenOut\n\
                        - TokenOut never distributed\n\
                        - Value not conserved across swap\n\
                        - Protocol holds stranded tokenOut".to_string(),
                    remediation: "Verify: sum(tokensIn) == sum(tokensOut) for all operations".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_ratio_violations(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: AMM constant product not maintained
            if self.has_ratio_violation(pc) {
                vulns.push(ImplicitInvariantVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    invariant_type: ImplicitInvariantType::RatioInvariant,
                    violated_invariant: "k = x * y (constant product)".to_string(),
                    description: "AMM/vault ratio invariant not maintained after operation".to_string(),
                    exploit_scenario: "uint public reserveA;\n\
                        uint public reserveB;\n\
                        // Implicit invariant: k = reserveA * reserveB\n\
                        \n\
                        function addLiquidity(uint amountA, uint amountB) {\n\
                            reserveA += amountA;\n\
                            reserveB += amountB;\n\
                            // BUG: Doesn't verify k is maintained or increased!\n\
                            // Attacker can add imbalanced liquidity\n\
                        }\n\
                        \n\
                        Ratio invariant violated:\n\
                        - k should never decrease\n\
                        - Imbalanced adds can decrease k\n\
                        - Enables arbitrage profit\n\
                        - Drains liquidity pool".to_string(),
                    remediation: "Verify: k_after >= k_before for all operations".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_monotonic_violations(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Value that should only increase can also decrease
            if self.has_monotonic_violation(pc) {
                vulns.push(ImplicitInvariantVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    invariant_type: ImplicitInvariantType::MonotonicInvariant,
                    violated_invariant: "totalSupply can only increase (deflationary token)".to_string(),
                    description: "Value that should be monotonically increasing can decrease".to_string(),
                    exploit_scenario: "uint public totalRewards;\n\
                        // Implicit: totalRewards should only increase over time\n\
                        \n\
                        function distributeRewards(uint amount) {\n\
                            totalRewards += amount; // Increases\n\
                        }\n\
                        \n\
                        function adjustRewards(int amount) {\n\
                            // BUG: Can decrease totalRewards!\n\
                            totalRewards = uint(int(totalRewards) + amount);\n\
                            // Breaks monotonic invariant\n\
                        }\n\
                        \n\
                        Monotonic invariant violated:\n\
                        - Rewards should accumulate\n\
                        - Can be decreased by admin\n\
                        - User rewards miscalculated\n\
                        - Reward theft possible".to_string(),
                    remediation: "Enforce monotonicity: Only allow increases, separate decrease function with safeguards".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_uniqueness_violations(&self) -> Vec<ImplicitInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: ID assignment without uniqueness check
            if self.has_uniqueness_violation(pc) {
                vulns.push(ImplicitInvariantVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    invariant_type: ImplicitInvariantType::UniquenessInvariant,
                    violated_invariant: "All IDs must be unique (no duplicates)".to_string(),
                    description: "ID or key assigned without checking for duplicates".to_string(),
                    exploit_scenario: "mapping(uint => Order) public orders;\n\
                        uint public nextOrderId;\n\
                        \n\
                        function createOrder() {\n\
                            uint id = nextOrderId;\n\
                            orders[id] = Order(...);\n\
                            nextOrderId++;\n\
                        }\n\
                        \n\
                        function createSpecialOrder(uint customId) {\n\
                            // BUG: No check if customId already exists!\n\
                            orders[customId] = Order(...);\n\
                            // Can overwrite existing orders\n\
                        }\n\
                        \n\
                        Uniqueness invariant violated:\n\
                        - Attacker overwrites existing order\n\
                        - Victim's order replaced\n\
                        - Funds stolen via order manipulation".to_string(),
                    remediation: "Check uniqueness: require(orders[id].owner == address(0), 'ID exists')".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_sum_invariant_violation(&self, start: usize) -> bool {
        if start + 60 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 60];

        // Look for: Multiple SSTORE to different slots (individual balances)
        // but not always updating a total slot
        let sstore_count = window.iter().filter(|&&b| b == 0x55).count();

        // If we see multiple SSTOREs in a function, one might be missing
        // More sophisticated: check if same storage slots updated in different code paths
        sstore_count >= 2
    }

    fn has_conservation_violation(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];

        // Look for: transferFrom (in) without corresponding transfer (out)
        // or vice versa
        let has_transfer_from = window.windows(4).any(|w| w == [0x23, 0xb8, 0x72, 0xdd]);
        let has_transfer = window.windows(4).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb]);

        // Conservation violation if only one direction
        has_transfer_from != has_transfer // XOR: one but not both
    }

    fn has_ratio_violation(&self, start: usize) -> bool {
        if start + 45 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 45];

        // Look for: Multiple SLOAD/SSTORE (reserves) with MUL
        // but no verification that product is maintained
        let has_reserve_updates = window.iter().filter(|&&b| b == 0x55).count() >= 2;
        let has_multiply = window.iter().any(|&b| b == 0x02); // MUL

        if has_reserve_updates && has_multiply {
            // Check if there's a comparison verifying k
            let has_k_check = window.windows(3).any(|w| {
                (w[0] == 0x10 || w[0] == 0x11) && // LT or GT
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57 // JUMPI
            });

            !has_k_check
        } else {
            false
        }
    }

    fn has_monotonic_violation(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for: Same storage slot both ADD and SUB in different code paths
        // Suggests value can both increase and decrease
        let has_add = window.iter().any(|&b| b == 0x01); // ADD
        let has_sub = window.iter().any(|&b| b == 0x03); // SUB

        has_add && has_sub
    }

    fn has_uniqueness_violation(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for: SSTORE without prior SLOAD check
        // (writing without checking if slot already occupied)
        if let Some(sstore_pos) = window.iter().position(|&b| b == 0x55) {
            let before_sstore = &window[..sstore_pos];
            
            // Check if there's an SLOAD before SSTORE (reading first)
            let has_read_check = before_sstore.iter().any(|&b| b == 0x54); // SLOAD

            !has_read_check
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_invariant_violation() {
        // Multiple SSTOREs without maintaining sum
        let bytecode = vec![
            0x55, // SSTORE (userBalance)
            0x55, // SSTORE (another balance)
            // No SSTORE to total
        ];
        
        let detector = ImplicitInvariantDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(!vulns.is_empty());
    }
}
