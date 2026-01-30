/// Context-Dependent Safety Analyzer
/// 
/// Detects code that's safe in isolation but unsafe when composed
/// Impact: $200M+ in exploits
/// 
/// Problem: Function works perfectly alone, breaks in specific contexts:
/// - Flash loan context (prices can be manipulated)
/// - Reentrancy context (state inconsistent mid-call)
/// - Multi-call context (state changes between calls)
/// - Upgrade context (storage layout changes)

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextDependentVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub vulnerability_type: ContextVulnerabilityType,
    pub safe_context: String,
    pub unsafe_context: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextVulnerabilityType {
    FlashLoanManipulable,        // Safe normally, exploitable with flash loan
    ReentrancyUnsafe,            // Safe alone, breaks with reentrant call
    MultiCallRace,               // Safe single call, race in multicall
    UpgradeUnsafe,               // Safe now, breaks after upgrade
    PausedButExecutable,         // Should be paused but still works
    StateDependentUnsafe,        // Safe in state A, unsafe in state B
    ComposabilityUnsafe,         // Safe alone, unsafe when composed
    OracleManipulable,           // Safe with honest oracle, exploitable if manipulated
}

pub struct ContextDependentSafetyAnalyzer {
    bytecode: Vec<u8>,
}

impl ContextDependentSafetyAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulnerabilities = Vec::new();

        // 1. Flash loan manipulable (price/oracle context)
        vulnerabilities.extend(self.detect_flash_loan_context());

        // 2. Reentrancy context unsafe
        vulnerabilities.extend(self.detect_reentrancy_context());

        // 3. Multi-call race conditions
        vulnerabilities.extend(self.detect_multicall_context());

        // 4. State-dependent safety violations
        vulnerabilities.extend(self.detect_state_context());

        // 5. Composability safety issues
        vulnerabilities.extend(self.detect_composability_context());

        vulnerabilities
    }

    fn detect_flash_loan_context(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Uses spot price/balance WITHOUT flash loan protection
            if self.is_flash_loan_exploitable(pc) {
                vulns.push(ContextDependentVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    vulnerability_type: ContextVulnerabilityType::FlashLoanManipulable,
                    safe_context: "Normal operations with organic liquidity".to_string(),
                    unsafe_context: "During flash loan, attacker controls reserves/prices".to_string(),
                    description: "Function uses manipulable price/balance, safe normally but exploitable with flash loan".to_string(),
                    exploit_scenario: "function withdraw(uint shares) {\n\
                            // Uses current price (spot price!)\n\
                            uint price = reserve1 / reserve0;\n\
                            uint assets = shares * price;\n\
                            _transfer(msg.sender, assets);\n\
                        }\n\
                        \n\
                        Safe context (normal):\n\
                        - reserve0 = 1000 ETH, reserve1 = 2000 DAI\n\
                        - price = 2 DAI/ETH\n\
                        - 100 shares → 200 DAI ✓ Correct\n\
                        \n\
                        Unsafe context (flash loan):\n\
                        1. Attacker flash loans 10000 ETH\n\
                        2. Swaps to manipulate: reserve0 = 11000, reserve1 = 200\n\
                        3. price = 0.0182 DAI/ETH (manipulated)\n\
                        4. withdraw(100 shares) → 1.82 DAI\n\
                        5. User gets 99% less than entitled\n\
                        6. Attacker profits from user's loss\n\
                        \n\
                        Same code, different context = exploitable".to_string(),
                    remediation: "Use TWAP instead of spot price, or add flash loan detection".to_string(),
                    confidence: 0.88,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_reentrancy_context(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: State read → external call → state use (unsafe if reentrant)
            if self.is_reentrant_context_unsafe(pc) {
                vulns.push(ContextDependentVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    vulnerability_type: ContextVulnerabilityType::ReentrancyUnsafe,
                    safe_context: "Single execution, no reentrancy".to_string(),
                    unsafe_context: "Reentrant call mid-execution, state inconsistent".to_string(),
                    description: "Function reads state, makes external call, then uses stale state".to_string(),
                    exploit_scenario: "function withdraw() {\n\
                            uint balance = balances[msg.sender]; // Read state\n\
                            (bool success,) = msg.sender.call{value: balance}(\"\"); // External call\n\
                            balances[msg.sender] = 0; // Update state AFTER call\n\
                        }\n\
                        \n\
                        Safe context (no reentrancy):\n\
                        - Read balance: 100 ETH\n\
                        - Transfer 100 ETH\n\
                        - Set balance to 0 ✓\n\
                        \n\
                        Unsafe context (reentrant):\n\
                        1. withdraw() called, balance = 100\n\
                        2. External call to attacker\n\
                        3. Attacker reenters withdraw() (balance still 100!)\n\
                        4. Withdraws another 100 ETH\n\
                        5. First call completes, sets balance = 0\n\
                        6. Second call completes, sets balance = 0\n\
                        7. Withdrew 200 ETH with 100 balance\n\
                        \n\
                        CEI pattern violated in reentrant context".to_string(),
                    remediation: "Add nonReentrant modifier or use checks-effects-interactions".to_string(),
                    confidence: 0.90,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_multicall_context(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Function assumes single execution but is multicallable
            if self.is_multicall_unsafe(pc) {
                vulns.push(ContextDependentVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: ContextVulnerabilityType::MultiCallRace,
                    safe_context: "Single function call per transaction".to_string(),
                    unsafe_context: "Multiple calls batched via multicall, state races".to_string(),
                    description: "Function safe alone, but state races when called multiple times in same tx".to_string(),
                    exploit_scenario: "function deposit(uint amount) {\n\
                            // Updates rewards based on CURRENT state\n\
                            updateRewards(); // Uses old totalDeposits\n\
                            totalDeposits += amount;\n\
                        }\n\
                        \n\
                        Safe context (single call):\n\
                        - deposit(100): rewards calculated correctly ✓\n\
                        \n\
                        Unsafe context (multicall):\n\
                        1. multicall([deposit(100), deposit(100)])\n\
                        2. First deposit: updateRewards() uses totalDeposits = 1000\n\
                        3. First deposit: totalDeposits = 1100\n\
                        4. Second deposit: updateRewards() uses totalDeposits = 1100 ✓\n\
                        5. But both use same block, should use 1000 for both!\n\
                        6. Rewards miscalculated\n\
                        7. Can exploit to claim excess rewards\n\
                        \n\
                        State consistency broken in batch context".to_string(),
                    remediation: "Add batch-atomic logic or prevent multicall on sensitive functions".to_string(),
                    confidence: 0.78,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_state_context(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Function safe in state A, unsafe in state B
            if self.is_state_dependent_unsafe(pc) {
                vulns.push(ContextDependentVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: ContextVulnerabilityType::StateDependentUnsafe,
                    safe_context: "Normal operating state (initialized, not paused)".to_string(),
                    unsafe_context: "Edge state (paused, upgrading, emergency)".to_string(),
                    description: "Function behaves correctly in normal state but unsafely in edge states".to_string(),
                    exploit_scenario: "function withdraw(uint amount) {\n\
                            // No pause check!\n\
                            balances[msg.sender] -= amount;\n\
                            token.transfer(msg.sender, amount);\n\
                        }\n\
                        \n\
                        Safe context (not paused):\n\
                        - Protocol operating normally\n\
                        - Withdraw works correctly ✓\n\
                        \n\
                        Unsafe context (paused):\n\
                        1. Critical bug discovered\n\
                        2. Admin pauses deposits/swaps\n\
                        3. But withdraw still works (no pause check!)\n\
                        4. Attacker withdraws during pause\n\
                        5. Drains protocol while fixing bug\n\
                        6. Pause mechanism ineffective\n\
                        \n\
                        Function ignores protocol state context".to_string(),
                    remediation: "Add whenNotPaused modifier to all critical functions".to_string(),
                    confidence: 0.82,
                });
            }

            pc += 1;
        }

        vulns
    }

    fn detect_composability_context(&self) -> Vec<ContextDependentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            // Pattern: Function assumes it's the only caller but can be composed
            if self.is_composability_unsafe(pc) {
                vulns.push(ContextDependentVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    vulnerability_type: ContextVulnerabilityType::ComposabilityUnsafe,
                    safe_context: "Direct user calls, simple execution path".to_string(),
                    unsafe_context: "Called via aggregator/router, complex composition".to_string(),
                    description: "Function safe when called directly, unsafe when composed in complex flows".to_string(),
                    exploit_scenario: "function swap(uint amountIn) returns (uint amountOut) {\n\
                            amountOut = getAmountOut(amountIn);\n\
                            // Assumes single swap per tx\n\
                            token.transfer(msg.sender, amountOut);\n\
                        }\n\
                        \n\
                        Safe context (direct call):\n\
                        - User calls swap(100) → receives 99 tokens ✓\n\
                        \n\
                        Unsafe context (composed via aggregator):\n\
                        1. Aggregator calls: swapA(100) → swapB(output) → swapC(output)\n\
                        2. swapA uses current reserves\n\
                        3. swapB sees swapA's impact on reserves\n\
                        4. swapC sees cumulative impact\n\
                        5. Price impact compounded\n\
                        6. Final output much worse than expected\n\
                        7. If aggregator doesn't check: user loses funds\n\
                        \n\
                        Composition context changes safety properties".to_string(),
                    remediation: "Add slippage protection, validate end-to-end output".to_string(),
                    confidence: 0.75,
                });
            }

            pc += 1;
        }

        vulns
    }

    // Helper functions

    fn is_flash_loan_exploitable(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for price calculation using division (spot price)
        // Pattern: BALANCE or SLOAD (reserves) → DIV → use immediately
        let has_price_calc = window.windows(3).any(|w| {
            (w[0] == 0x47 || w[0] == 0x54) && // BALANCE or SLOAD
            w[1] == 0x54 && // Another SLOAD (other reserve)
            w[2] == 0x04    // DIV (price = reserve1 / reserve0)
        });

        if has_price_calc {
            // Check if there's TWAP or flash loan protection
            let has_protection = window.windows(3).any(|w| {
                w[0] == 0x42 && // TIMESTAMP (TWAP check)
                w[1] == 0x03    // SUB
            });

            !has_protection
        } else {
            false
        }
    }

    fn is_reentrant_context_unsafe(&self, start: usize) -> bool {
        if start + 45 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 45];

        // Look for: SLOAD → CALL → SSTORE pattern (read-call-write)
        let sload_pos = window.iter().position(|&b| b == 0x54);
        let call_pos = window.iter().position(|&b| b == 0xF1 || b == 0xF4);
        let sstore_pos = window.iter().position(|&b| b == 0x55);

        matches!((sload_pos, call_pos, sstore_pos), 
                 (Some(sl), Some(c), Some(ss)) if sl < c && c < ss)
    }

    fn is_multicall_unsafe(&self, start: usize) -> bool {
        if start + 35 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 35];

        // Look for state updates that depend on current state
        // Pattern: SLOAD (state) → operation → SSTORE (state)
        // Without batch-atomicity protection
        let state_updates = window.windows(3).filter(|w| {
            w[0] == 0x54 && // SLOAD
            (w[1] == 0x01 || w[1] == 0x03) && // ADD or SUB
            w[2] == 0x55    // SSTORE
        }).count();

        state_updates >= 2 // Multiple state updates suggest multicall risk
    }

    fn is_state_dependent_unsafe(&self, start: usize) -> bool {
        if start + 30 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 30];

        // Look for critical operation WITHOUT pause/state check
        let has_critical_op = window.iter().any(|&b| {
            b == 0x55 || // SSTORE (state change)
            b == 0xF1    // CALL (transfer)
        });

        if has_critical_op {
            // Check if there's a pause/state flag check
            let has_state_check = window.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD (state flag)
                w[1] == 0x15 && // ISZERO (check)
                w[2] == 0x57    // JUMPI (revert if wrong state)
            });

            !has_state_check
        } else {
            false
        }
    }

    fn is_composability_unsafe(&self, start: usize) -> bool {
        if start + 40 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 40];

        // Look for functions that return values used by caller
        // But don't validate intermediate states
        let has_return = window.iter().any(|&b| b == 0xF3); // RETURN

        if has_return {
            // Check if there's end-to-end validation
            let has_output_check = window.windows(3).any(|w| {
                w[0] == 0x10 && // LT (output >= minOutput)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI
            });

            !has_output_check
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flash_loan_exploitable() {
        // Spot price calculation
        let bytecode = vec![
            0x54, // SLOAD (reserve0)
            0x54, // SLOAD (reserve1)
            0x04, // DIV (price)
            // No TWAP protection
        ];
        
        let analyzer = ContextDependentSafetyAnalyzer::new(bytecode);
        let vulns = analyzer.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ContextVulnerabilityType::FlashLoanManipulable)));
    }
}
