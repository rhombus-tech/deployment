/// Lending Utilization Rate Manipulation Detector
///
/// Detects manipulation of utilization rates in lending protocols (Aave, Compound, etc.).
/// Utilization rate = borrowed / total_supply → determines interest rates.
///
/// Why dangerous:
/// - Flash loan → borrow all available liquidity → 100% utilization
/// - Interest rate spikes (can go 100x+)
/// - Liquidations triggered by rate spike
/// - Profitable for attacker while harming protocol users
///
/// Utilization rate formula:
/// ```
/// utilization = totalBorrow / totalSupply
/// borrowRate = baseRate + utilization * slope
/// 
/// Example:
/// - Normal: 50% utilized → 5% APY
/// - Attack: 99.9% utilized → 500% APY!
/// ```
///
/// Real exploits:
/// - Multiple Aave rate manipulation: $2M+
/// - Compound interest rate attacks
/// - Venus Protocol exploitation
/// - Cream Finance rate manipulation
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableLending {
///     uint256 public totalSupply;
///     uint256 public totalBorrow;
///     
///     function getBorrowRate() public view returns (uint256) {
///         // ❌ Can be manipulated via flash loan!
///         uint256 utilization = totalBorrow * 1e18 / totalSupply;
///         
///         // Rate spikes at high utilization
///         if (utilization > 0.9e18) {
///             return 100e18; // 100% APY!
///         }
///         return 5e18; // 5% APY
///     }
///     
///     function borrow(uint256 amount) external {
///         // Borrow at current rate
///         uint256 rate = getBorrowRate();
///         
///         // If flash loan borrows 99% of supply,
///         // rate suddenly 100% → existing borrowers liquidated!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LendingUtilizationVulnerability {
    pub vulnerability_type: UtilizationIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UtilizationIssueType {
    UnprotectedUtilizationCalc,    // Utilization calculated without manipulation protection
    NoUtilizationCap,              // No cap on utilization rate
    InterestRateSpikeRisk,         // Interest rate can spike dangerously
    FlashLoanUtilizationAttack,    // Flash loan can manipulate utilization
    KinkRateTooLow,                // Kink point too low (easy to reach 100% util)
}

pub struct LendingUtilizationRateDetector {
    bytecode: Vec<u8>,
}

impl LendingUtilizationRateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LendingUtilizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_utilization_calculation());
        vulnerabilities.extend(self.detect_interest_rate_calculation());

        vulnerabilities
    }

    fn detect_utilization_calculation(&self) -> Vec<LendingUtilizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for division operations (utilization = borrow / supply)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x04 { // DIV
                // Check if this looks like utilization calculation
                if self.has_lending_pattern_before(i) {
                    vulnerabilities.push(LendingUtilizationVulnerability {
                        vulnerability_type: UtilizationIssueType::UnprotectedUtilizationCalc,
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: "Potential utilization rate calculation detected - verify flash loan protection".to_string(),
                        exploit_scenario: format!(
                            "UTILIZATION RATE CALCULATION at position {}:\n\
                            \n\
                            Division operation in lending context detected.\n\
                            \n\
                            FLASH LOAN MANIPULATION ATTACK:\n\
                            ```solidity\n\
                            contract VulnerableLendingPool {{\n\
                                uint256 public totalSupply = 1000 ether;\n\
                                uint256 public totalBorrow = 500 ether;  // 50% utilized\n\
                                \n\
                                function getUtilizationRate() public view returns (uint256) {{\n\
                                    // ❌ Can be manipulated!\n\
                                    return totalBorrow * 1e18 / totalSupply;\n\
                                }}\n\
                                \n\
                                function getBorrowRate() public view returns (uint256) {{\n\
                                    uint256 util = getUtilizationRate();\n\
                                    \n\
                                    // Interest rate model (simplified)\n\
                                    if (util < 0.8e18) {{\n\
                                        return util / 10;  // Low rate below 80%\n\
                                    }} else {{\n\
                                        return util * 5;   // High rate above 80%\n\
                                    }}\n\
                                }}\n\
                                \n\
                                function borrow(uint256 amount) external {{\n\
                                    require(totalBorrow + amount <= totalSupply, 'Insufficient liquidity');\n\
                                    \n\
                                    uint256 rate = getBorrowRate();\n\
                                    totalBorrow += amount;\n\
                                    \n\
                                    // Interest accrues at 'rate'\n\
                                }}\n\
                            }}\n\
                            \n\
                            // ATTACK:\n\
                            contract Attacker {{\n\
                                function exploit(VulnerableLendingPool pool) external {{\n\
                                    // Step 1: Flash loan 900 ETH from pool\n\
                                    pool.borrow(900 ether);\n\
                                    \n\
                                    // Now: totalBorrow = 1400, totalSupply = 1000\n\
                                    // Wait... this would revert (insufficient liquidity)\n\
                                    \n\
                                    // Better attack:\n\
                                    // Flash loan from different pool, deposit here\n\
                                }}\n\
                                \n\
                                function betterExploit() external {{\n\
                                    // Get flash loan from Aave (10,000 ETH)\n\
                                    \n\
                                    // Deposit 9,000 ETH to target pool\n\
                                    // Now totalSupply = 10,000 ETH\n\
                                    \n\
                                    // Borrow 9,500 ETH\n\
                                    // Now totalBorrow = 10,000 ETH\n\
                                    // Utilization = 100%!\n\
                                    \n\
                                    // Interest rate spikes to 500%\n\
                                    \n\
                                    // Wait 1 block\n\
                                    // Everyone's interest accrues at 500%\n\
                                    \n\
                                    // Repay flash loan\n\
                                    // Keep profit from rate manipulation\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL EXPLOIT PATTERN:\n\
                            \n\
                            1. BEFORE ATTACK:\n\
                            ```\n\
                            Supply:  1,000 ETH\n\
                            Borrow:    500 ETH\n\
                            Util:      50%\n\
                            Rate:      5% APY\n\
                            ```\n\
                            \n\
                            2. ATTACKER FLASH LOANS 10,000 ETH:\n\
                            ```\n\
                            Supply:  11,000 ETH (attacker deposits 10k)\n\
                            Borrow:     500 ETH\n\
                            Util:       4.5%\n\
                            Rate:       0.45% APY (low)\n\
                            ```\n\
                            \n\
                            3. ATTACKER BORROWS MAXIMUM:\n\
                            ```\n\
                            Supply:  11,000 ETH\n\
                            Borrow:  10,800 ETH (attacker borrows 10,300)\n\
                            Util:      98%\n\
                            Rate:     490% APY (SPIKE!)\n\
                            ```\n\
                            \n\
                            4. IMPACT ON EXISTING BORROWERS:\n\
                            ```\n\
                            - Their debt accrues at 490% APY\n\
                            - In 1 hour: debt increases ~5%\n\
                            - Liquidation threshold reached\n\
                            - Positions liquidated\n\
                            - Attacker profits from liquidations\n\
                            ```\n\
                            \n\
                            5. ATTACKER EXITS:\n\
                            ```\n\
                            - Repays 10,300 ETH borrow\n\
                            - Withdraws 10,000 ETH supply\n\
                            - Repays flash loan\n\
                            - Keeps profit\n\
                            ```\n\
                            \n\
                            AAVE PROTECTION MECHANISMS:\n\
                            \n\
                            1. Reserve Factor:\n\
                            ```solidity\n\
                            // Only 80% of deposits can be borrowed\n\
                            uint256 availableLiquidity = totalSupply * 0.8;\n\
                            require(totalBorrow + amount <= availableLiquidity);\n\
                            ```\n\
                            \n\
                            2. Kink Interest Rate Model:\n\
                            ```solidity\n\
                            function getBorrowRate(uint256 util) public pure returns (uint256) {{\n\
                                if (util <= OPTIMAL_UTIL) {{  // e.g., 80%\n\
                                    // Below kink: linear, low slope\n\
                                    return BASE_RATE + util * SLOPE1 / OPTIMAL_UTIL;\n\
                                }} else {{\n\
                                    // Above kink: steep slope\n\
                                    uint256 excessUtil = util - OPTIMAL_UTIL;\n\
                                    return BASE_RATE + SLOPE1 + excessUtil * SLOPE2;\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            3. Utilization Cap:\n\
                            ```solidity\n\
                            uint256 constant MAX_UTILIZATION = 0.95e18; // 95%\n\
                            \n\
                            function borrow(uint256 amount) external {{\n\
                                uint256 newUtil = (totalBorrow + amount) * 1e18 / totalSupply;\n\
                                require(newUtil <= MAX_UTILIZATION, 'Utilization too high');\n\
                                // Prevents reaching 100% util\n\
                            }}\n\
                            ```\n\
                            \n\
                            4. Time-Weighted Rates:\n\
                            ```solidity\n\
                            // Don't use instant utilization\n\
                            // Use time-weighted average\n\
                            uint256 avgUtil = getTimeWeightedUtilization();\n\
                            ```\n\
                            \n\
                            COMPOUND'S APPROACH:\n\
                            ```solidity\n\
                            function getBorrowRate() public view returns (uint256) {{\n\
                                uint256 util = getCashPrior() == 0 ? 0 : \n\
                                    totalBorrows * 1e18 / (totalReserves + totalBorrows + getCashPrior());\n\
                                \n\
                                // Jump rate model\n\
                                if (util <= kink) {{\n\
                                    return multiplierPerBlock * util / 1e18 + baseRatePerBlock;\n\
                                }} else {{\n\
                                    uint256 normalRate = multiplierPerBlock * kink / 1e18 + baseRatePerBlock;\n\
                                    uint256 excessUtil = util - kink;\n\
                                    return normalRate + jumpMultiplierPerBlock * excessUtil / 1e18;\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            PROTECTION CHECKLIST:\n\
                            ✓ Reserve factor (max 80-90% borrowable)\n\
                            ✓ Kink interest rate model\n\
                            ✓ Maximum utilization cap\n\
                            ✓ Interest rate limits (max 1000% APY)\n\
                            ✓ Flash loan resistance\n\
                            ✓ Time-weighted utilization\n\
                            \n\
                            SEVERITY: HIGH\n\
                            - Can liquidate existing users\n\
                            - Rate spike causes losses\n\
                            - Flash loan makes it profitable",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_interest_rate_calculation(&self) -> Vec<LendingUtilizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for multiplication followed by division (rate calculation)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x02 { // MUL
                for j in i..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        vulnerabilities.push(LendingUtilizationVulnerability {
                            vulnerability_type: UtilizationIssueType::InterestRateSpikeRisk,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.60,
                            description: "Interest rate calculation detected - verify spike protection".to_string(),
                            exploit_scenario: format!(
                                "INTEREST RATE CALCULATION at position {}:\n\
                                \n\
                                MUL followed by DIV pattern detected.\n\
                                Typical of interest rate calculation: rate = base + util * multiplier / divisor\n\
                                \n\
                                Verify:\n\
                                - Rate cannot spike infinitely\n\
                                - Maximum rate cap exists\n\
                                - Kink model prevents instant 100x rate\n\
                                - Flash loan cannot manipulate util in single block",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    fn has_lending_pattern_before(&self, pos: usize) -> bool {
        // Heuristic: Check for operations that look like lending math
        // Multiple DIV, MUL operations in proximity suggest financial calculations
        let mut math_ops = 0;
        for i in pos.saturating_sub(50)..pos {
            if self.bytecode[i] == 0x02 || // MUL
               self.bytecode[i] == 0x04 || // DIV
               self.bytecode[i] == 0x01 {  // ADD
                math_ops += 1;
            }
        }
        math_ops >= 3
    }
}
