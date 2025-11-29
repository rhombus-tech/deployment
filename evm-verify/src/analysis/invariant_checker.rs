// Business Logic Invariant Checker
// Detects violations of protocol-specific invariants (the business logic bugs audits catch)

use serde::{Serialize, Deserialize};
use ethers::types::{U256, Address};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub invariant_rule: String,
    pub violation_details: String,
    pub violation_path: Vec<ExecutionStep>,
    pub severity: InvariantSeverity,
    pub confidence: f64,
    pub example_exploit: ExploitScenario,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvariantSeverity {
    Critical,  // Protocol can be drained
    High,      // Significant value loss
    Medium,    // Logic error, limited impact
    Low,       // Edge case violation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub function_name: String,
    pub inputs: HashMap<String, String>,
    pub state_before: HashMap<String, String>,
    pub state_after: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitScenario {
    pub description: String,
    pub attack_steps: Vec<String>,
    pub profit_estimate: u128,
}

/// Protocol invariant definition
#[derive(Debug, Clone)]
pub struct Invariant {
    pub name: String,
    pub rule: InvariantRule,
    pub priority: InvariantPriority,
}

#[derive(Debug, Clone)]
pub enum InvariantRule {
    /// Total supply equals sum of all balances
    TokenSupplyBalance,
    /// Debt never exceeds collateral * ratio
    CollateralRatio { min_ratio: f64 },
    /// Reserve always above minimum
    ReserveRequirement { min_reserve: U256 },
    /// User balance never exceeds total supply
    BalanceBound,
    /// Price within acceptable bounds
    PriceBound { min_price: U256, max_price: U256 },
    /// Custom invariant with symbolic expression
    Custom { expression: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantPriority {
    Critical,  // Must never be violated
    High,      // Should not be violated
    Medium,    // Important but may have edge cases
}

pub struct InvariantChecker {
    invariants: Vec<Invariant>,
    bytecode: Vec<u8>,
    symbolic_engine: SymbolicExecutionEngine,
}

impl InvariantChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut invariants = Vec::new();
        
        // Add common DeFi invariants
        invariants.push(Invariant {
            name: "Token Supply Consistency".to_string(),
            rule: InvariantRule::TokenSupplyBalance,
            priority: InvariantPriority::Critical,
        });
        
        invariants.push(Invariant {
            name: "Collateral Ratio Maintained".to_string(),
            rule: InvariantRule::CollateralRatio { min_ratio: 1.5 },
            priority: InvariantPriority::Critical,
        });
        
        invariants.push(Invariant {
            name: "Balance Cannot Exceed Supply".to_string(),
            rule: InvariantRule::BalanceBound,
            priority: InvariantPriority::Critical,
        });

        Self {
            invariants,
            bytecode: bytecode.clone(),
            symbolic_engine: SymbolicExecutionEngine::new(bytecode),
        }
    }

    /// Add custom invariant from protocol specification
    pub fn add_custom_invariant(&mut self, name: String, expression: String, priority: InvariantPriority) {
        self.invariants.push(Invariant {
            name,
            rule: InvariantRule::Custom { expression },
            priority,
        });
    }

    /// Parse invariants from contract NatSpec comments
    pub fn parse_natspec_invariants(&mut self, source_code: &str) {
        // Look for @invariant tags in comments
        for line in source_code.lines() {
            if line.contains("@invariant") {
                if let Some(invariant) = self.extract_invariant_from_comment(line) {
                    self.invariants.push(invariant);
                }
            }
        }
    }

    /// Main analysis: Check all invariants
    pub fn check_invariants(&mut self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Clone invariants to avoid borrow checker issues
        let invariants = self.invariants.clone();
        for invariant in &invariants {
            if let Some(violation) = self.check_single_invariant(invariant) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Check a single invariant across all execution paths
    fn check_single_invariant(&mut self, invariant: &Invariant) -> Option<InvariantViolation> {
        match &invariant.rule {
            InvariantRule::TokenSupplyBalance => self.check_token_supply_invariant(invariant),
            InvariantRule::CollateralRatio { min_ratio } => self.check_collateral_ratio(invariant, *min_ratio),
            InvariantRule::ReserveRequirement { min_reserve } => self.check_reserve_requirement(invariant, *min_reserve),
            InvariantRule::BalanceBound => self.check_balance_bound(invariant),
            InvariantRule::PriceBound { min_price, max_price } => self.check_price_bound(invariant, *min_price, *max_price),
            InvariantRule::Custom { expression } => self.check_custom_invariant(invariant, expression),
        }
    }

    /// Check: totalSupply == sum(all balances)
    fn check_token_supply_invariant(&mut self, invariant: &Invariant) -> Option<InvariantViolation> {
        // Find storage slots for totalSupply and balances mapping
        let total_supply_slot = self.find_total_supply_slot()?;
        let balances_slot = self.find_balances_mapping_slot()?;

        // Use symbolic execution to find if there's a path where:
        // totalSupply != sum(balances[user1] + balances[user2] + ...)
        
        let violation_path = self.symbolic_engine.find_path_where(|state| {
            let total_supply = state.read_storage(total_supply_slot);
            let balance_sum = state.sum_all_balances(balances_slot);
            total_supply != balance_sum
        })?;

        Some(InvariantViolation {
            invariant_name: invariant.name.clone(),
            invariant_rule: "totalSupply == sum(balances)".to_string(),
            violation_details: "Function allows totalSupply to diverge from sum of balances".to_string(),
            violation_path: self.convert_symbolic_path(violation_path),
            severity: InvariantSeverity::Critical,
            confidence: 0.95,
            example_exploit: ExploitScenario {
                description: "Attacker can mint tokens without updating totalSupply or vice versa".to_string(),
                attack_steps: vec![
                    "1. Call vulnerable function with specific parameters".to_string(),
                    "2. Balance increases without totalSupply increase".to_string(),
                    "3. Infinite token minting possible".to_string(),
                ],
                profit_estimate: u128::MAX, // Unlimited
            },
            remediation: "Ensure all balance updates are paired with totalSupply updates. Use SafeMath.".to_string(),
        })
    }

    /// Check: debt <= collateral * min_ratio
    fn check_collateral_ratio(&mut self, invariant: &Invariant, min_ratio: f64) -> Option<InvariantViolation> {
        // Find storage slots for debt and collateral
        let debt_slot = self.find_debt_slot()?;
        let collateral_slot = self.find_collateral_slot()?;

        let violation_path = self.symbolic_engine.find_path_where(|state| {
            let debt = state.read_storage(debt_slot).as_u128() as f64;
            let collateral = state.read_storage(collateral_slot).as_u128() as f64;
            debt > collateral * min_ratio
        })?;

        Some(InvariantViolation {
            invariant_name: invariant.name.clone(),
            invariant_rule: format!("debt <= collateral * {}", min_ratio),
            violation_details: "Function allows under-collateralized borrowing".to_string(),
            violation_path: self.convert_symbolic_path(violation_path),
            severity: InvariantSeverity::Critical,
            confidence: 0.90,
            example_exploit: ExploitScenario {
                description: "Attacker can borrow more than collateral allows".to_string(),
                attack_steps: vec![
                    "1. Deposit minimal collateral".to_string(),
                    "2. Call borrow() with manipulated parameters".to_string(),
                    "3. Withdraw borrowed funds without sufficient collateral".to_string(),
                    "4. Protocol becomes insolvent".to_string(),
                ],
                profit_estimate: 1_000_000_000_000_000_000_000u128, // $1M
            },
            remediation: format!("Add explicit check: require(debt <= collateral * {})", min_ratio),
        })
    }

    /// Check: user balance <= totalSupply
    fn check_balance_bound(&mut self, invariant: &Invariant) -> Option<InvariantViolation> {
        let total_supply_slot = self.find_total_supply_slot()?;
        let balances_slot = self.find_balances_mapping_slot()?;

        let violation_path = self.symbolic_engine.find_path_where(|state| {
            let total_supply = state.read_storage(total_supply_slot);
            let user_balance = state.read_mapping(balances_slot, state.symbolic_address());
            user_balance > total_supply
        })?;

        Some(InvariantViolation {
            invariant_name: invariant.name.clone(),
            invariant_rule: "balanceOf(user) <= totalSupply".to_string(),
            violation_details: "User can have more tokens than total supply".to_string(),
            violation_path: self.convert_symbolic_path(violation_path),
            severity: InvariantSeverity::Critical,
            confidence: 0.92,
            example_exploit: ExploitScenario {
                description: "Integer overflow or unchecked transfer allows balance > supply".to_string(),
                attack_steps: vec![
                    "1. Call transfer with crafted amount".to_string(),
                    "2. Receiver balance overflows past totalSupply".to_string(),
                    "3. Attacker has more tokens than should exist".to_string(),
                ],
                profit_estimate: u128::MAX,
            },
            remediation: "Use SafeMath and check balance <= totalSupply after transfers".to_string(),
        })
    }

    /// Check reserve requirement
    fn check_reserve_requirement(&mut self, invariant: &Invariant, min_reserve: U256) -> Option<InvariantViolation> {
        let reserve_slot = self.find_reserve_slot()?;

        let violation_path = self.symbolic_engine.find_path_where(|state| {
            let current_reserve = state.read_storage(reserve_slot);
            current_reserve < min_reserve
        })?;

        Some(InvariantViolation {
            invariant_name: invariant.name.clone(),
            invariant_rule: format!("reserve >= {}", min_reserve),
            violation_details: "Reserve can drop below minimum requirement".to_string(),
            violation_path: self.convert_symbolic_path(violation_path),
            severity: InvariantSeverity::High,
            confidence: 0.85,
            example_exploit: ExploitScenario {
                description: "Protocol becomes insolvent".to_string(),
                attack_steps: vec![
                    "1. Exploit allows reserve depletion".to_string(),
                    "2. Protocol cannot honor withdrawals".to_string(),
                ],
                profit_estimate: min_reserve.as_u128(),
            },
            remediation: format!("require(reserve >= {})", min_reserve),
        })
    }

    /// Check price bounds
    fn check_price_bound(&mut self, invariant: &Invariant, min_price: U256, max_price: U256) -> Option<InvariantViolation> {
        let price_slot = self.find_price_slot()?;

        let violation_path = self.symbolic_engine.find_path_where(|state| {
            let price = state.read_storage(price_slot);
            price < min_price || price > max_price
        })?;

        Some(InvariantViolation {
            invariant_name: invariant.name.clone(),
            invariant_rule: format!("{} <= price <= {}", min_price, max_price),
            violation_details: "Price can be manipulated outside acceptable bounds".to_string(),
            violation_path: self.convert_symbolic_path(violation_path),
            severity: InvariantSeverity::High,
            confidence: 0.80,
            example_exploit: ExploitScenario {
                description: "Price manipulation attack".to_string(),
                attack_steps: vec![
                    "1. Manipulate oracle or internal price".to_string(),
                    "2. Extract value at manipulated price".to_string(),
                ],
                profit_estimate: 100_000_000_000_000_000_000u128, // $100k
            },
            remediation: format!("Add price bounds check: require(price >= {} && price <= {})", min_price, max_price),
        })
    }

    /// Check custom invariant
    fn check_custom_invariant(&mut self, invariant: &Invariant, expression: &str) -> Option<InvariantViolation> {
        // Parse and evaluate custom expression
        // This is complex - would need a full expression parser
        // For now, return None (not implemented)
        None
    }

    // === HELPER METHODS ===

    fn extract_invariant_from_comment(&self, comment: &str) -> Option<Invariant> {
        // Parse: /// @invariant totalSupply == sum(balances)
        if let Some(expr_start) = comment.find("@invariant") {
            let expression = comment[expr_start + 10..].trim().to_string();
            Some(Invariant {
                name: "Custom Invariant".to_string(),
                rule: InvariantRule::Custom { expression },
                priority: InvariantPriority::High,
            })
        } else {
            None
        }
    }

    fn find_total_supply_slot(&self) -> Option<U256> {
        // Heuristic: totalSupply is often at slot 2 or 3 in ERC20 contracts
        // In production, would analyze storage layout more carefully
        Some(U256::from(2))
    }

    fn find_balances_mapping_slot(&self) -> Option<U256> {
        // balanceOf mapping often at slot 0 or 1
        Some(U256::from(0))
    }

    fn find_debt_slot(&self) -> Option<U256> {
        Some(U256::from(5))
    }

    fn find_collateral_slot(&self) -> Option<U256> {
        Some(U256::from(6))
    }

    fn find_reserve_slot(&self) -> Option<U256> {
        Some(U256::from(7))
    }

    fn find_price_slot(&self) -> Option<U256> {
        Some(U256::from(8))
    }

    fn convert_symbolic_path(&self, _path: SymbolicPath) -> Vec<ExecutionStep> {
        // Convert symbolic execution path to human-readable steps
        vec![] // Placeholder
    }
}

// === SYMBOLIC EXECUTION ENGINE (Simplified) ===

struct SymbolicExecutionEngine {
    bytecode: Vec<u8>,
}

impl SymbolicExecutionEngine {
    fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    fn find_path_where<F>(&mut self, _condition: F) -> Option<SymbolicPath>
    where
        F: Fn(&SymbolicState) -> bool,
    {
        // This is where the magic happens
        // In production, would use Z3 or similar SMT solver
        // For now, return None (not yet implemented)
        None
    }
}

#[derive(Clone)]
struct SymbolicState {
    storage: HashMap<U256, U256>,
}

impl SymbolicState {
    fn read_storage(&self, slot: U256) -> U256 {
        *self.storage.get(&slot).unwrap_or(&U256::zero())
    }

    fn read_mapping(&self, _base_slot: U256, _key: Address) -> U256 {
        U256::zero()
    }

    fn sum_all_balances(&self, _balances_slot: U256) -> U256 {
        U256::zero()
    }

    fn symbolic_address(&self) -> Address {
        Address::zero()
    }
}

struct SymbolicPath {
    // Path through execution tree
}
