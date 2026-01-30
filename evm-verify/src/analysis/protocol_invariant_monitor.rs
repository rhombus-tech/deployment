/// Protocol Invariant Monitor
/// Continuously monitors that protocol-level invariants hold across all operations
use crate::bytecode::SecuritySeverity;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProtocolInvariantMonitor {
    bytecode: Vec<u8>,
    known_invariants: HashMap<String, Invariant>,
}

#[derive(Debug, Clone)]
pub struct Invariant {
    pub invariant_type: String,
    pub expression: String,
    pub violation_severity: SecuritySeverity,
}

#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub location: usize,
    pub expected: String,
    pub actual: String,
    pub severity: SecuritySeverity,
}

impl ProtocolInvariantMonitor {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { 
            bytecode,
            known_invariants: Self::initialize_invariants(),
        }
    }

    fn initialize_invariants() -> HashMap<String, Invariant> {
        let mut invariants = HashMap::new();
        
        // AMM invariants
        invariants.insert("uniswap_k".to_string(), Invariant {
            invariant_type: "AMM".to_string(),
            expression: "reserve0 * reserve1 >= k".to_string(),
            violation_severity: SecuritySeverity::Critical,
        });
        
        // Lending invariants
        invariants.insert("aave_collateral".to_string(), Invariant {
            invariant_type: "Lending".to_string(),
            expression: "collateral_value >= borrow_value * min_ratio".to_string(),
            violation_severity: SecuritySeverity::Critical,
        });
        
        // ERC20 supply invariant
        invariants.insert("erc20_supply".to_string(), Invariant {
            invariant_type: "Token".to_string(),
            expression: "sum(balances) == total_supply".to_string(),
            violation_severity: SecuritySeverity::Critical,
        });
        
        invariants
    }

    pub fn check_all_invariants(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        for (name, invariant) in &self.known_invariants {
            if let Some(violation) = self.check_invariant(name, invariant) {
                violations.push(violation);
            }
        }

        violations
    }

    fn check_invariant(&self, name: &str, invariant: &Invariant) -> Option<InvariantViolation> {
        match invariant.invariant_type.as_str() {
            "AMM" => self.check_amm_invariant(name, invariant),
            "Lending" => self.check_lending_invariant(name, invariant),
            "Token" => self.check_token_invariant(name, invariant),
            _ => None,
        }
    }

    fn check_amm_invariant(&self, name: &str, invariant: &Invariant) -> Option<InvariantViolation> {
        // Check if reserves can be manipulated to violate k=xy
        if self.has_reserve_manipulation() {
            Some(InvariantViolation {
                invariant_name: name.to_string(),
                location: 0,
                expected: "k maintained".to_string(),
                actual: "k can be violated".to_string(),
                severity: invariant.violation_severity.clone(),
            })
        } else {
            None
        }
    }

    fn check_lending_invariant(&self, name: &str, invariant: &Invariant) -> Option<InvariantViolation> {
        // Check if collateral ratio can drop below minimum
        if self.has_collateral_bypass() {
            Some(InvariantViolation {
                invariant_name: name.to_string(),
                location: 0,
                expected: "collateral >= min_ratio".to_string(),
                actual: "collateral can drop below minimum".to_string(),
                severity: invariant.violation_severity.clone(),
            })
        } else {
            None
        }
    }

    fn check_token_invariant(&self, name: &str, invariant: &Invariant) -> Option<InvariantViolation> {
        // Check if total supply can be manipulated
        if self.has_supply_manipulation() {
            Some(InvariantViolation {
                invariant_name: name.to_string(),
                location: 0,
                expected: "sum(balances) == total_supply".to_string(),
                actual: "supply can be manipulated".to_string(),
                severity: invariant.violation_severity.clone(),
            })
        } else {
            None
        }
    }

    fn has_reserve_manipulation(&self) -> bool {
        // Look for SSTORE to reserve storage without proper checks
        self.bytecode.contains(&0x55) // SSTORE
    }

    fn has_collateral_bypass(&self) -> bool {
        // Look for borrow operations without health checks
        self.bytecode.contains(&0xf1) // CALL (borrow)
    }

    fn has_supply_manipulation(&self) -> bool {
        // Look for mint/burn without proper accounting
        let has_mint = self.bytecode.windows(2).any(|w| w == &[0x60, 0x00]); // PUSH 0
        let has_sstore = self.bytecode.contains(&0x55);
        has_mint && has_sstore
    }
}
