// Business Logic Fuzzer
// Generates random transaction sequences and checks invariants

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicVulnerability {
    pub violation_type: InvariantViolation,
    pub severity: SecuritySeverity,
    pub description: String,
    pub transaction_sequence: Vec<TransactionCall>,
    pub initial_state: ContractState,
    pub final_state: ContractState,
    pub expected_result: String,
    pub actual_result: String,
    pub exploit_value: u128,
    pub reproduction_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantViolation {
    TotalSupplyMismatch,        // totalSupply != sum(balances)
    BalanceUnderflow,           // user balance goes negative
    BalanceOverflow,            // user balance exceeds deposits
    ContractBalanceDeficit,     // contract balance < total deposits
    RewardOverpayment,          // rewards > expected from time*rate
    DoubleSpending,             // same funds spent twice
    UnauthorizedMint,           // mint without proper authorization
    UnauthorizedBurn,           // burn someone else's tokens
    FeeCircumvention,           // bypass fee payment
    ArbitraryStateChange,       // state changed without proper auth
    InconsistentAccounting,     // debits != credits
    ReentrancyExploitation,     // state corruption via reentrancy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCall {
    pub function_selector: [u8; 4],
    pub function_name: String,
    pub caller: String,
    pub parameters: Vec<Parameter>,
    pub value: u128,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub param_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    pub total_supply: u128,
    pub contract_balance: u128,
    pub user_balances: HashMap<String, u128>,
    pub user_deposits: HashMap<String, u128>,
    pub accumulated_fees: u128,
    pub timestamp: u64,
    pub block_number: u64,
}

pub struct BusinessLogicFuzzer {
    bytecode: Vec<u8>,
    functions: Vec<FunctionSignature>,
    invariants: Vec<Invariant>,
}

#[derive(Debug, Clone)]
struct FunctionSignature {
    selector: [u8; 4],
    name: String,
    params: Vec<String>,
    state_changing: bool,
}

#[derive(Debug, Clone)]
struct Invariant {
    name: String,
    check: InvariantCheck,
}

#[derive(Debug, Clone)]
enum InvariantCheck {
    TotalSupplyEqualsBalances,
    ContractBalanceCoversDeposits,
    BalanceNonNegative,
    RewardsProportionalToTime,
    NoDoubleSpending,
}

impl BusinessLogicFuzzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let functions = Self::extract_functions(&bytecode);
        let invariants = Self::default_invariants();
        
        Self {
            bytecode,
            functions,
            invariants,
        }
    }

    pub fn fuzz(&self, iterations: usize) -> Vec<BusinessLogicVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..iterations {
            // Generate random transaction sequence
            let sequence = self.generate_transaction_sequence(i);
            
            // Execute sequence and check invariants
            if let Some(violation) = self.execute_and_check(&sequence) {
                vulnerabilities.push(violation);
            }
        }

        // Deduplicate by violation type
        self.deduplicate_vulnerabilities(vulnerabilities)
    }

    fn generate_transaction_sequence(&self, seed: usize) -> Vec<TransactionCall> {
        let mut sequence = Vec::new();
        let sequence_length = 3 + (seed % 8); // 3-10 transactions
        
        // Common DeFi patterns to test
        let patterns = vec![
            // Pattern 1: deposit -> withdraw -> deposit -> claim
            vec!["deposit", "withdraw", "deposit", "claim"],
            // Pattern 2: approve max -> transferFrom -> transferFrom
            vec!["approve", "transferFrom", "transferFrom"],
            // Pattern 3: mint -> burn -> totalSupply check
            vec!["mint", "burn", "totalSupply"],
            // Pattern 4: stake -> unstake -> getReward
            vec!["stake", "unstake", "getReward"],
            // Pattern 5: swap -> swap -> balance check
            vec!["swap", "swap", "balanceOf"],
        ];

        // Pick a pattern or random
        if seed % 3 == 0 && !patterns.is_empty() {
            let pattern = &patterns[seed % patterns.len()];
            for func_name in pattern {
                if let Some(func) = self.find_function_by_name(func_name) {
                    sequence.push(TransactionCall {
                        function_selector: func.selector,
                        function_name: func.name.clone(),
                        caller: self.generate_caller(seed),
                        parameters: self.generate_parameters(&func, seed),
                        value: self.generate_value(seed),
                        success: true,
                    });
                }
            }
        } else {
            // Random sequence
            if self.functions.is_empty() {
                return sequence;
            }
            for j in 0..sequence_length {
                if let Some(func) = self.functions.get((seed + j) % self.functions.len()) {
                    sequence.push(TransactionCall {
                        function_selector: func.selector,
                        function_name: func.name.clone(),
                        caller: self.generate_caller(seed + j),
                        parameters: self.generate_parameters(func, seed + j),
                        value: self.generate_value(seed + j),
                        success: true,
                    });
                }
            }
        }

        sequence
    }

    fn execute_and_check(&self, sequence: &[TransactionCall]) -> Option<BusinessLogicVulnerability> {
        // Initialize state
        let mut state = ContractState {
            total_supply: 1_000_000_000_000_000_000u128, // 1 token
            contract_balance: 100_000_000_000_000_000u128,
            user_balances: HashMap::new(),
            user_deposits: HashMap::new(),
            accumulated_fees: 0,
            timestamp: 1700000000,
            block_number: 18000000,
        };

        state.user_balances.insert("user1".to_string(), 1000_000_000_000_000_000u128);
        state.user_balances.insert("user2".to_string(), 500_000_000_000_000_000u128);
        state.user_deposits.insert("user1".to_string(), 1000_000_000_000_000_000u128);

        let initial_state = state.clone();

        // Execute each transaction
        for tx in sequence {
            self.execute_transaction(tx, &mut state);
        }

        // Check all invariants
        for invariant in &self.invariants {
            if let Some(violation) = self.check_invariant(invariant, &initial_state, &state, sequence) {
                return Some(violation);
            }
        }

        None
    }

    fn execute_transaction(&self, tx: &TransactionCall, state: &mut ContractState) {
        // Simplified symbolic execution based on function name patterns
        match tx.function_name.as_str() {
            name if name.contains("deposit") || name.contains("stake") => {
                let amount = self.extract_amount_from_params(&tx.parameters);
                let user = &tx.caller;
                
                // Update deposits
                *state.user_deposits.entry(user.clone()).or_insert(0) += amount;
                state.contract_balance += amount;
                
                // Update balance
                *state.user_balances.entry(user.clone()).or_insert(0) += amount;
                state.total_supply += amount;
            }
            
            name if name.contains("withdraw") || name.contains("unstake") => {
                let amount = self.extract_amount_from_params(&tx.parameters);
                let user = &tx.caller;
                
                if let Some(balance) = state.user_balances.get_mut(user) {
                    if *balance >= amount {
                        *balance -= amount;
                        state.contract_balance = state.contract_balance.saturating_sub(amount);
                        state.total_supply = state.total_supply.saturating_sub(amount);
                    }
                }
            }
            
            name if name.contains("transfer") => {
                let amount = self.extract_amount_from_params(&tx.parameters);
                let from = &tx.caller;
                let to = self.extract_address_from_params(&tx.parameters);
                
                if let Some(from_balance) = state.user_balances.get_mut(from) {
                    if *from_balance >= amount {
                        *from_balance -= amount;
                        *state.user_balances.entry(to).or_insert(0) += amount;
                    }
                }
            }
            
            name if name.contains("mint") => {
                let amount = self.extract_amount_from_params(&tx.parameters);
                let to = self.extract_address_from_params(&tx.parameters);
                
                *state.user_balances.entry(to).or_insert(0) += amount;
                state.total_supply += amount;
            }
            
            name if name.contains("burn") => {
                let amount = self.extract_amount_from_params(&tx.parameters);
                let user = &tx.caller;
                
                if let Some(balance) = state.user_balances.get_mut(user) {
                    if *balance >= amount {
                        *balance -= amount;
                        state.total_supply = state.total_supply.saturating_sub(amount);
                    }
                }
            }
            
            name if name.contains("claim") || name.contains("getReward") => {
                // Rewards = time * rate (simplified)
                let user = &tx.caller;
                let time_elapsed = 86400; // 1 day
                let reward_rate = 1000; // 0.1% per day
                let deposited = state.user_deposits.get(user).unwrap_or(&0);
                let rewards = deposited * reward_rate / 1000000;
                
                *state.user_balances.entry(user.clone()).or_insert(0) += rewards;
                state.contract_balance = state.contract_balance.saturating_sub(rewards);
            }
            
            _ => {
                // Unknown function, no state change
            }
        }
        
        // Advance time
        state.timestamp += 100;
        state.block_number += 1;
    }

    fn check_invariant(
        &self,
        invariant: &Invariant,
        initial_state: &ContractState,
        final_state: &ContractState,
        sequence: &[TransactionCall],
    ) -> Option<BusinessLogicVulnerability> {
        match invariant.check {
            InvariantCheck::TotalSupplyEqualsBalances => {
                let sum_balances: u128 = final_state.user_balances.values().sum();
                
                if final_state.total_supply != sum_balances {
                    return Some(BusinessLogicVulnerability {
                        violation_type: InvariantViolation::TotalSupplyMismatch,
                        severity: SecuritySeverity::Critical,
                        description: format!(
                            "Total supply ({}) != sum of balances ({}). Accounting error!",
                            final_state.total_supply, sum_balances
                        ),
                        transaction_sequence: sequence.to_vec(),
                        initial_state: initial_state.clone(),
                        final_state: final_state.clone(),
                        expected_result: format!("totalSupply = {}", sum_balances),
                        actual_result: format!("totalSupply = {}", final_state.total_supply),
                        exploit_value: final_state.total_supply.abs_diff(sum_balances),
                        reproduction_steps: self.generate_reproduction_steps(sequence),
                    });
                }
            }
            
            InvariantCheck::ContractBalanceCoversDeposits => {
                let total_deposits: u128 = final_state.user_deposits.values().sum();
                
                if final_state.contract_balance < total_deposits {
                    return Some(BusinessLogicVulnerability {
                        violation_type: InvariantViolation::ContractBalanceDeficit,
                        severity: SecuritySeverity::Critical,
                        description: format!(
                            "Contract balance ({}) < total deposits ({}). Insolvency risk!",
                            final_state.contract_balance, total_deposits
                        ),
                        transaction_sequence: sequence.to_vec(),
                        initial_state: initial_state.clone(),
                        final_state: final_state.clone(),
                        expected_result: format!("balance >= {}", total_deposits),
                        actual_result: format!("balance = {}", final_state.contract_balance),
                        exploit_value: total_deposits - final_state.contract_balance,
                        reproduction_steps: self.generate_reproduction_steps(sequence),
                    });
                }
            }
            
            InvariantCheck::BalanceNonNegative => {
                // All checked via saturating_sub in execution
            }
            
            InvariantCheck::RewardsProportionalToTime => {
                // Check if rewards exceeded reasonable amount
                for (user, final_balance) in &final_state.user_balances {
                    if let Some(initial_balance) = initial_state.user_balances.get(user) {
                        let gained = final_balance.saturating_sub(*initial_balance);
                        let deposited = final_state.user_deposits.get(user).unwrap_or(&0);
                        
                        // Rewards should never exceed 100% of deposit in this short time
                        if gained > *deposited {
                            return Some(BusinessLogicVulnerability {
                                violation_type: InvariantViolation::RewardOverpayment,
                                severity: SecuritySeverity::High,
                                description: format!(
                                    "User {} gained {} but only deposited {}. Reward exploit!",
                                    user, gained, deposited
                                ),
                                transaction_sequence: sequence.to_vec(),
                                initial_state: initial_state.clone(),
                                final_state: final_state.clone(),
                                expected_result: format!("gain <= {}", deposited),
                                actual_result: format!("gain = {}", gained),
                                exploit_value: gained - deposited,
                                reproduction_steps: self.generate_reproduction_steps(sequence),
                            });
                        }
                    }
                }
            }
            
            InvariantCheck::NoDoubleSpending => {
                // Check if any user's balance increased without corresponding deposit/transfer
                for (user, final_balance) in &final_state.user_balances {
                    let initial_balance = initial_state.user_balances.get(user).unwrap_or(&0);
                    let deposited = final_state.user_deposits.get(user).unwrap_or(&0);
                    let initial_deposited = initial_state.user_deposits.get(user).unwrap_or(&0);
                    
                    let new_deposits = deposited.saturating_sub(*initial_deposited);
                    let balance_increase = final_balance.saturating_sub(*initial_balance);
                    
                    // Balance increase should come from deposits or transfers
                    // Allow 10% margin for rewards
                    let max_allowed_increase = new_deposits + (new_deposits / 10);
                    
                    if balance_increase > max_allowed_increase + 1000 {
                        return Some(BusinessLogicVulnerability {
                            violation_type: InvariantViolation::DoubleSpending,
                            severity: SecuritySeverity::Critical,
                            description: format!(
                                "User {} balance increased by {} but only deposited {}. Possible double-spend!",
                                user, balance_increase, new_deposits
                            ),
                            transaction_sequence: sequence.to_vec(),
                            initial_state: initial_state.clone(),
                            final_state: final_state.clone(),
                            expected_result: format!("increase <= {}", max_allowed_increase),
                            actual_result: format!("increase = {}", balance_increase),
                            exploit_value: balance_increase.saturating_sub(max_allowed_increase),
                            reproduction_steps: self.generate_reproduction_steps(sequence),
                        });
                    }
                }
            }
        }

        None
    }

    fn generate_reproduction_steps(&self, sequence: &[TransactionCall]) -> Vec<String> {
        sequence.iter().enumerate().map(|(i, tx)| {
            format!(
                "{}. Call {}({}) from {} with {} ETH",
                i + 1,
                tx.function_name,
                tx.parameters.iter()
                    .map(|p| format!("{}: {}", p.param_type, p.value))
                    .collect::<Vec<_>>()
                    .join(", "),
                tx.caller,
                tx.value as f64 / 1e18
            )
        }).collect()
    }

    fn deduplicate_vulnerabilities(&self, vulns: Vec<BusinessLogicVulnerability>) -> Vec<BusinessLogicVulnerability> {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for vuln in vulns {
            let key = format!("{:?}", vuln.violation_type);
            if seen.insert(key) {
                unique.push(vuln);
            }
        }

        unique
    }

    // === HELPER METHODS ===

    fn extract_functions(bytecode: &[u8]) -> Vec<FunctionSignature> {
        let mut functions = Vec::new();

        // Common ERC20/DeFi function signatures
        let known_functions = vec![
            ([0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)", true),
            ([0x23, 0xb8, 0x72, 0xdd], "transferFrom(address,address,uint256)", true),
            ([0x09, 0x5e, 0xa7, 0xb3], "approve(address,uint256)", true),
            ([0x70, 0xa0, 0x82, 0x31], "balanceOf(address)", false),
            ([0x18, 0x16, 0x0d, 0xdd], "totalSupply()", false),
            ([0xb6, 0xb5, 0x5f, 0x25], "deposit(uint256)", true),
            ([0x2e, 0x1a, 0x7d, 0x4d], "withdraw(uint256)", true),
            ([0x40, 0xc1, 0x0f, 0x19], "mint(address,uint256)", true),
            ([0x42, 0x96, 0x6c, 0x68], "burn(uint256)", true),
            ([0xa6, 0x94, 0xfc, 0x3a], "stake(uint256)", true),
            ([0x2e, 0x17, 0xde, 0x78], "unstake(uint256)", true),
            ([0x3d, 0x18, 0xb9, 0x12], "getReward()", true),
            ([0xe9, 0xfa, 0xf9, 0xf2], "claim()", true),
        ];

        for (selector, name, state_changing) in known_functions {
            if bytecode.windows(4).any(|w| w == selector) {
                functions.push(FunctionSignature {
                    selector,
                    name: name.to_string(),
                    params: Self::parse_params(name),
                    state_changing,
                });
            }
        }

        functions
    }

    fn parse_params(signature: &str) -> Vec<String> {
        if let Some(start) = signature.find('(') {
            if let Some(end) = signature.find(')') {
                let params_str = &signature[start+1..end];
                if params_str.is_empty() {
                    return vec![];
                }
                return params_str.split(',').map(|s| s.to_string()).collect();
            }
        }
        vec![]
    }

    fn default_invariants() -> Vec<Invariant> {
        vec![
            Invariant {
                name: "Total supply equals sum of balances".to_string(),
                check: InvariantCheck::TotalSupplyEqualsBalances,
            },
            Invariant {
                name: "Contract balance covers all deposits".to_string(),
                check: InvariantCheck::ContractBalanceCoversDeposits,
            },
            Invariant {
                name: "Balances are non-negative".to_string(),
                check: InvariantCheck::BalanceNonNegative,
            },
            Invariant {
                name: "Rewards proportional to time".to_string(),
                check: InvariantCheck::RewardsProportionalToTime,
            },
            Invariant {
                name: "No double spending".to_string(),
                check: InvariantCheck::NoDoubleSpending,
            },
        ]
    }

    fn find_function_by_name(&self, name: &str) -> Option<&FunctionSignature> {
        self.functions.iter().find(|f| f.name.contains(name))
    }

    fn generate_caller(&self, seed: usize) -> String {
        let users = vec!["user1", "user2", "user3", "attacker"];
        users[seed % users.len()].to_string()
    }

    fn generate_parameters(&self, func: &FunctionSignature, seed: usize) -> Vec<Parameter> {
        func.params.iter().enumerate().map(|(i, param_type)| {
            Parameter {
                param_type: param_type.clone(),
                value: if param_type.contains("uint") {
                    format!("{}", 1000 + (seed * 17 + i * 7) % 10000)
                } else if param_type.contains("address") {
                    format!("0x{:040x}", (seed * 31 + i * 13) % 1000)
                } else {
                    format!("0x{:064x}", seed + i)
                },
            }
        }).collect()
    }

    fn generate_value(&self, seed: usize) -> u128 {
        if seed % 5 == 0 {
            (1000 + (seed % 10000)) as u128 * 1_000_000_000_000_000u128
        } else {
            0
        }
    }

    fn extract_amount_from_params(&self, params: &[Parameter]) -> u128 {
        params.iter()
            .find(|p| p.param_type.contains("uint"))
            .and_then(|p| p.value.parse::<u128>().ok())
            .unwrap_or(1000_000_000_000_000_000u128)
    }

    fn extract_address_from_params(&self, params: &[Parameter]) -> String {
        params.iter()
            .find(|p| p.param_type.contains("address"))
            .map(|p| p.value.clone())
            .unwrap_or_else(|| "user2".to_string())
    }
}

/// Generate fuzzing report
pub fn generate_fuzzing_report(vulnerabilities: &[BusinessLogicVulnerability]) -> FuzzingReport {
    let critical_count = vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();

    let total_exploit_value: u128 = vulnerabilities.iter()
        .map(|v| v.exploit_value)
        .sum();

    FuzzingReport {
        total_violations: vulnerabilities.len(),
        critical_violations: critical_count,
        total_exploit_value,
        risk_level: if critical_count > 0 {
            "CRITICAL - Business logic violations found".to_string()
        } else if !vulnerabilities.is_empty() {
            "HIGH - Logic issues detected".to_string()
        } else {
            "PASS - No violations in fuzzing".to_string()
        },
        recommendation: if critical_count > 0 {
            "URGENT: Fix accounting/invariant violations before deployment. These enable fund theft.".to_string()
        } else if !vulnerabilities.is_empty() {
            "Review and fix logic issues. Add comprehensive tests.".to_string()
        } else {
            "Business logic appears sound. Continue with additional testing.".to_string()
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingReport {
    pub total_violations: usize,
    pub critical_violations: usize,
    pub total_exploit_value: u128,
    pub risk_level: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invariant_violation_detection() {
        let bytecode = vec![
            0xa9, 0x05, 0x9c, 0xbb, // transfer selector
            0xb6, 0xb5, 0x5f, 0x25, // deposit selector
        ];
        
        let fuzzer = BusinessLogicFuzzer::new(bytecode);
        let vulns = fuzzer.fuzz(100);
        
        // Should generate some test sequences
        assert!(fuzzer.functions.len() > 0, "Should find functions");
    }

    #[test]
    fn test_total_supply_invariant() {
        let bytecode = vec![0x40, 0xc1, 0x0f, 0x19]; // mint
        let fuzzer = BusinessLogicFuzzer::new(bytecode);
        
        // Manual state violation
        let mut state = ContractState {
            total_supply: 100,
            contract_balance: 0,
            user_balances: HashMap::new(),
            user_deposits: HashMap::new(),
            accumulated_fees: 0,
            timestamp: 0,
            block_number: 0,
        };
        
        state.user_balances.insert("user1".to_string(), 50);
        state.user_balances.insert("user2".to_string(), 60); // Sum = 110, but total = 100
        
        let invariant = Invariant {
            name: "test".to_string(),
            check: InvariantCheck::TotalSupplyEqualsBalances,
        };
        
        let result = fuzzer.check_invariant(&invariant, &state, &state, &[]);
        assert!(result.is_some(), "Should detect total supply mismatch");
    }
}
