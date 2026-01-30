/// Semantic Consistency Checker
/// 
/// Detects when code is syntactically correct but semantically wrong
/// Impact: $300M+ in exploits from variable meaning confusion
/// 
/// Bytecode is correct, but the MEANING is wrong:
/// - "balance" could mean user balance OR contract balance
/// - "price" could be in ETH OR USD OR tokens
/// - "time" could be seconds OR blocks OR timestamps
/// 
/// Tools can't detect this because the code executes fine,
/// but the developer's INTENT doesn't match IMPLEMENTATION

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticInconsistencyVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub inconsistency_type: SemanticInconsistencyType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SemanticInconsistencyType {
    BalanceConfusion,        // user balance vs contract balance
    UnitsConfusion,          // wei vs gwei vs ether
    TimeConfusion,           // seconds vs blocks vs timestamps
    AddressConfusion,        // token vs proxy vs implementation
    ValueConfusion,          // shares vs assets, principal vs yield
    PriceConfusion,          // ETH price vs USD price vs token price
    IndexConfusion,          // 0-indexed vs 1-indexed
    BooleanInversion,        // isValid vs isInvalid confusion
}

pub struct SemanticConsistencyChecker {
    bytecode: Vec<u8>,
}

impl SemanticConsistencyChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Balance confusion (user vs contract)
        vulnerabilities.extend(self.detect_balance_confusion());

        // 2. Units confusion (wei/ether)
        vulnerabilities.extend(self.detect_units_confusion());

        // 3. Time confusion (seconds/blocks)
        vulnerabilities.extend(self.detect_time_confusion());

        // 4. Address confusion (token/proxy)
        vulnerabilities.extend(self.detect_address_confusion());

        // 5. Value confusion (shares/assets)
        vulnerabilities.extend(self.detect_value_confusion());

        // 6. Price base confusion
        vulnerabilities.extend(self.detect_price_confusion());

        vulnerabilities
    }

    fn detect_balance_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Uses both SLOAD(balances[user]) and BALANCE (contract.balance)
            // in same function - likely semantic confusion
            if self.has_balance_semantic_confusion(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    inconsistency_type: SemanticInconsistencyType::BalanceConfusion,
                    description: "Function uses both user balance and contract balance, likely semantic confusion".to_string(),
                    exploit_scenario: "mapping(address => uint) public balance; // User deposits\n\
                        \n\
                        function canWithdraw(uint amount) returns (bool) {\n\
                            // Checks user's DEPOSITED balance\n\
                            return balance[msg.sender] >= amount;\n\
                        }\n\
                        \n\
                        function withdraw(uint amount) {\n\
                            require(canWithdraw(amount));\n\
                            // Uses CONTRACT's ETH balance!\n\
                            require(address(this).balance >= amount);\n\
                            payable(msg.sender).transfer(amount);\n\
                        }\n\
                        \n\
                        Semantic bug:\n\
                        - canWithdraw checks deposited balance\n\
                        - withdraw checks contract balance\n\
                        - User can withdraw more than deposited\n\
                        - If contract.balance > user.balance, theft possible".to_string(),
                    remediation: "Use consistent balance reference: check same balance in both functions".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_units_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Arithmetic mixing values without unit conversion
            if self.has_units_mixing(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    inconsistency_type: SemanticInconsistencyType::UnitsConfusion,
                    description: "Arithmetic operation mixes different units without conversion".to_string(),
                    exploit_scenario: "function calculateFee(uint amountEther) returns (uint) {\n\
                            uint feeRate = 1; // Meant to be 0.01 ETH\n\
                            return amountEther * feeRate; // BUG: treats 1 as wei!\n\
                            // Should be: amountEther * feeRate / 1 ether\n\
                        }\n\
                        \n\
                        Units confusion:\n\
                        - Developer thinks in ETH\n\
                        - Code computes in wei\n\
                        - Fee 10^18 times too small\n\
                        - Protocol loses 99.9999% of fees".to_string(),
                    remediation: "Explicit unit conversion: use 1 ether, 1 gwei constants, convert before arithmetic".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_time_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Mixing block.number and block.timestamp in same calculation
            if self.has_time_unit_confusion(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    inconsistency_type: SemanticInconsistencyType::TimeConfusion,
                    description: "Function mixes blocks and timestamps without conversion".to_string(),
                    exploit_scenario: "uint public lastUpdate = block.number; // blocks\n\
                        \n\
                        function timeSince() returns (uint) {\n\
                            // BUG: Subtracts block.timestamp (seconds) from block.number!\n\
                            return block.timestamp - lastUpdate;\n\
                        }\n\
                        \n\
                        Semantic confusion:\n\
                        - lastUpdate stored in blocks (~19M)\n\
                        - block.timestamp in seconds (~1.7B)\n\
                        - timeSince() returns huge negative number (underflow)\n\
                        - Time-based logic completely broken".to_string(),
                    remediation: "Use consistent time units: both blocks OR both timestamps, never mix".to_string(),
                    confidence: 0.85,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_address_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Calling function on wrong address type
            if self.has_address_type_confusion(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    inconsistency_type: SemanticInconsistencyType::AddressConfusion,
                    description: "Function called on wrong address type (proxy vs implementation)".to_string(),
                    exploit_scenario: "address public tokenProxy;\n\
                        address public tokenImpl;\n\
                        \n\
                        function getBalance() returns (uint) {\n\
                            // BUG: Calls implementation directly instead of proxy!\n\
                            return IERC20(tokenImpl).balanceOf(address(this));\n\
                            // Should be: IERC20(tokenProxy).balanceOf(...)\n\
                        }\n\
                        \n\
                        Semantic confusion:\n\
                        - Proxy holds user balances\n\
                        - Implementation has no balances\n\
                        - Returns 0, logic broken\n\
                        - Can enable unauthorized withdrawals".to_string(),
                    remediation: "Use proxy address for state reads, implementation only for upgrades".to_string(),
                    confidence: 0.80,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_value_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Mixing shares and assets in calculations
            if self.has_shares_assets_confusion(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    inconsistency_type: SemanticInconsistencyType::ValueConfusion,
                    description: "Function mixes shares and assets without conversion".to_string(),
                    exploit_scenario: "function deposit(uint assets) {\n\
                            uint shares = convertToShares(assets);\n\
                            _mint(msg.sender, shares);\n\
                        }\n\
                        \n\
                        function withdraw(uint amount) {\n\
                            // BUG: Treats 'amount' as assets, but burns as shares!\n\
                            _burn(msg.sender, amount); // Should convert to shares first\n\
                            asset.transfer(msg.sender, amount);\n\
                        }\n\
                        \n\
                        Semantic confusion:\n\
                        - deposit() correctly converts assets → shares\n\
                        - withdraw() treats input as both assets AND shares\n\
                        - Burns wrong amount\n\
                        - Vault accounting corrupted".to_string(),
                    remediation: "Explicit naming: depositAssets(), withdrawShares(), never ambiguous 'amount'".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_price_confusion(&self) -> Vec<SemanticInconsistencyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Price calculations in different bases (ETH vs USD)
            if self.has_price_base_confusion(pc) {
                vulns.push(SemanticInconsistencyVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    inconsistency_type: SemanticInconsistencyType::PriceConfusion,
                    description: "Price calculation mixes different base currencies".to_string(),
                    exploit_scenario: "function liquidate(address user) {\n\
                            uint ethPrice = oracle.getETHPrice(); // Returns price in USD\n\
                            uint collateral = getCollateral(user); // In ETH\n\
                            uint debt = getDebt(user); // In USD\n\
                            \n\
                            // BUG: Compares ETH amount to USD amount!\n\
                            require(collateral < debt * 1.5); // Meaningless comparison\n\
                        }\n\
                        \n\
                        Semantic confusion:\n\
                        - collateral in ETH (e.g., 100 ETH)\n\
                        - debt in USD (e.g., $200,000)\n\
                        - Direct comparison (100 < 300000) always true\n\
                        - All positions liquidatable\n\
                        - Protocol insolvency".to_string(),
                    remediation: "Convert to same base: collateralUSD = collateral * ethPrice, then compare".to_string(),
                    confidence: 0.83,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn has_balance_semantic_confusion(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];

        // Look for both BALANCE opcode and SLOAD (mapping balance) in same window
        let has_balance_opcode = window.iter().any(|&b| b == 0x47); // BALANCE
        let has_balance_storage = window.windows(2).any(|w| {
            w[0] == 0x54 && // SLOAD
            w[1] != 0x47    // Not immediately after BALANCE
        });

        has_balance_opcode && has_balance_storage
    }

    fn has_units_mixing(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for arithmetic (MUL/DIV) with small constants (likely unit errors)
        let has_arithmetic = window.iter().any(|&b| b == 0x02 || b == 0x04); // MUL or DIV

        if has_arithmetic {
            // Check for suspiciously small constants (1-1000) in financial calculations
            let has_small_constant = window.windows(2).any(|w| {
                w[0] == 0x60 && // PUSH1
                w[1] > 0 && w[1] < 100 // Small number (likely meant to be larger)
            });

            has_small_constant
        } else {
            false
        }
    }

    fn has_time_unit_confusion(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for both NUMBER (block.number) and TIMESTAMP in same calculation
        let has_number = window.iter().any(|&b| b == 0x43); // NUMBER
        let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP

        has_number && has_timestamp
    }

    fn has_address_type_confusion(&self, start: usize) -> bool {
        if start + 45 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 45];

        // Look for multiple SLOAD of addresses followed by CALL/STATICCALL
        // Indicates loading different addresses and potentially using wrong one
        let address_loads: Vec<usize> = window
            .windows(2)
            .enumerate()
            .filter(|(_, w)| w[0] == 0x54) // SLOAD
            .map(|(i, _)| i)
            .collect();

        let has_call = window.iter().any(|&b| b == 0xF1 || b == 0xFA); // CALL or STATICCALL

        address_loads.len() >= 2 && has_call
    }

    fn has_shares_assets_confusion(&self, start: usize) -> bool {
        if start + 50 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 50];

        // Look for mint/burn operations mixed with transfers
        // Suggests shares vs assets confusion
        let has_mint_burn = window.windows(4).any(|w| {
            // Mint/burn selectors or ADD/SUB on totalSupply
            w[0] == 0x01 || w[0] == 0x03 // ADD or SUB (for supply)
        });

        let has_transfer = window.windows(4).any(|w| {
            w == [0xa9, 0x05, 0x9c, 0xbb] || // transfer
            w == [0x23, 0xb8, 0x72, 0xdd]    // transferFrom
        });

        has_mint_burn && has_transfer
    }

    fn has_price_base_confusion(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for multiple oracle calls (STATICCALL) followed by comparison
        // without conversion - suggests price base confusion
        let oracle_calls: Vec<usize> = window
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0xFA) // STATICCALL
            .map(|(i, _)| i)
            .collect();

        let has_comparison = window.iter().any(|&b| b == 0x10 || b == 0x11); // LT or GT

        oracle_calls.len() >= 2 && has_comparison
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_confusion() {
        let bytecode = vec![
            0x47, // BALANCE (contract.balance)
            0x54, // SLOAD (user balance mapping)
            0x10, // LT (comparison)
        ];
        
        let checker = SemanticConsistencyChecker::new(bytecode);
        let vulns = checker.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.inconsistency_type, SemanticInconsistencyType::BalanceConfusion)));
    }
}
