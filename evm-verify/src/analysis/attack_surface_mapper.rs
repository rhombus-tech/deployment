/// Attack Surface Mapper
/// Maps ALL entry points and possible attack vectors in a contract
use crate::bytecode::SecuritySeverity;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct AttackSurfaceMapper {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttackSurface {
    pub entry_points: Vec<EntryPoint>,
    pub attack_vectors: Vec<AttackVector>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flows: Vec<DataFlow>,
    pub total_surface_score: f64,
}

#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub function_selector: u32,
    pub is_payable: bool,
    pub is_external: bool,
    pub access_control: AccessLevel,
    pub complexity: u32,
}

#[derive(Debug, Clone)]
pub struct AttackVector {
    pub vector_type: String,
    pub entry_point: u32,
    pub exploitability: f64,
    pub impact: SecuritySeverity,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct TrustBoundary {
    pub boundary_type: String,
    pub location: usize,
    pub is_validated: bool,
}

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub from: String,
    pub to: String,
    pub is_trusted: bool,
    pub sanitization: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessLevel {
    Public,       // Anyone can call
    Restricted,   // Has access control
    Owner,        // Only owner
    Internal,     // Not externally callable
}

impl AttackSurfaceMapper {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn map_attack_surface(&self) -> AttackSurface {
        let entry_points = self.identify_entry_points();
        let attack_vectors = self.identify_attack_vectors(&entry_points);
        let trust_boundaries = self.identify_trust_boundaries();
        let data_flows = self.map_data_flows();
        let total_surface_score = self.calculate_surface_score(&entry_points, &attack_vectors);

        AttackSurface {
            entry_points,
            attack_vectors,
            trust_boundaries,
            data_flows,
            total_surface_score,
        }
    }

    fn identify_entry_points(&self) -> Vec<EntryPoint> {
        let mut entry_points = Vec::new();
        
        // Extract function selectors (PUSH4 followed by EQ for dispatcher pattern)
        for i in 0..self.bytecode.len().saturating_sub(7) {
            if self.bytecode[i] == 0x63 { // PUSH4
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);

                // Check characteristics
                let is_payable = self.is_function_payable(i);
                let access_control = self.determine_access_level(i);
                let complexity = self.estimate_function_complexity(i);

                entry_points.push(EntryPoint {
                    function_selector: selector,
                    is_payable,
                    is_external: true, // If in dispatcher, it's external
                    access_control,
                    complexity,
                });
            }
        }

        entry_points
    }

    fn identify_attack_vectors(&self, entry_points: &[EntryPoint]) -> Vec<AttackVector> {
        let mut vectors = Vec::new();

        for entry in entry_points {
            // Reentrancy vectors
            if self.has_external_calls_near_selector(entry.function_selector) {
                vectors.push(AttackVector {
                    vector_type: "Reentrancy".to_string(),
                    entry_point: entry.function_selector,
                    exploitability: 0.8,
                    impact: SecuritySeverity::Critical,
                    description: "Function makes external calls - reentrancy risk".to_string(),
                });
            }

            // Integer overflow vectors (if no SafeMath)
            if self.has_arithmetic_near_selector(entry.function_selector) && !self.has_overflow_checks() {
                vectors.push(AttackVector {
                    vector_type: "Integer Overflow".to_string(),
                    entry_point: entry.function_selector,
                    exploitability: 0.7,
                    impact: SecuritySeverity::High,
                    description: "Unchecked arithmetic operations".to_string(),
                });
            }

            // Access control vectors
            if matches!(entry.access_control, AccessLevel::Public) && self.has_state_changes(entry.function_selector) {
                vectors.push(AttackVector {
                    vector_type: "Unauthorized Access".to_string(),
                    entry_point: entry.function_selector,
                    exploitability: 0.9,
                    impact: SecuritySeverity::Critical,
                    description: "Public function can modify state".to_string(),
                });
            }

            // DOS vectors
            if entry.complexity > 100 {
                vectors.push(AttackVector {
                    vector_type: "Denial of Service".to_string(),
                    entry_point: entry.function_selector,
                    exploitability: 0.6,
                    impact: SecuritySeverity::Medium,
                    description: "High complexity function - potential DOS".to_string(),
                });
            }

            // Price manipulation vectors
            if entry.is_payable && self.has_price_calculations(entry.function_selector) {
                vectors.push(AttackVector {
                    vector_type: "Price Manipulation".to_string(),
                    entry_point: entry.function_selector,
                    exploitability: 0.7,
                    impact: SecuritySeverity::High,
                    description: "Payable function with price calculations".to_string(),
                });
            }
        }

        vectors
    }

    fn identify_trust_boundaries(&self) -> Vec<TrustBoundary> {
        let mut boundaries = Vec::new();

        // External calls are trust boundaries
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0xf1 || byte == 0xf4 || byte == 0xfa { // CALL, DELEGATECALL, STATICCALL
                let is_validated = self.has_validation_before(i);
                boundaries.push(TrustBoundary {
                    boundary_type: "External Call".to_string(),
                    location: i,
                    is_validated,
                });
            }
        }

        // User inputs are trust boundaries (CALLDATALOAD)
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x35 { // CALLDATALOAD
                let is_validated = self.has_validation_after(i);
                boundaries.push(TrustBoundary {
                    boundary_type: "User Input".to_string(),
                    location: i,
                    is_validated,
                });
            }
        }

        boundaries
    }

    fn map_data_flows(&self) -> Vec<DataFlow> {
        let mut flows = Vec::new();

        // CALLDATALOAD -> SSTORE (user input to storage)
        flows.push(DataFlow {
            from: "User Input".to_string(),
            to: "Storage".to_string(),
            is_trusted: false,
            sanitization: self.has_input_validation(),
        });

        // SLOAD -> CALL (storage to external call)
        flows.push(DataFlow {
            from: "Storage".to_string(),
            to: "External Contract".to_string(),
            is_trusted: true,
            sanitization: false,
        });

        flows
    }

    fn calculate_surface_score(&self, entry_points: &[EntryPoint], vectors: &[AttackVector]) -> f64 {
        let entry_score = entry_points.len() as f64 * 2.0;
        let public_entry_score = entry_points.iter()
            .filter(|e| matches!(e.access_control, AccessLevel::Public))
            .count() as f64 * 5.0;
        let vector_score: f64 = vectors.iter()
            .map(|v| v.exploitability * 10.0)
            .sum();

        entry_score + public_entry_score + vector_score
    }

    // Helper methods
    fn is_function_payable(&self, selector_location: usize) -> bool {
        // Check for CALLVALUE (0x34) check near function
        self.bytecode[selector_location..selector_location.saturating_add(50)]
            .iter()
            .any(|&b| b == 0x34)
    }

    fn determine_access_level(&self, selector_location: usize) -> AccessLevel {
        // Check for access control patterns within 100 bytes
        let range = selector_location..selector_location.saturating_add(100);
        
        if self.bytecode.get(range.clone())
            .map(|slice| slice.windows(2).any(|w| w == &[0x33, 0x14]))
            .unwrap_or(false)
        {
            AccessLevel::Restricted
        } else {
            AccessLevel::Public
        }
    }

    fn estimate_function_complexity(&self, _selector_location: usize) -> u32 {
        // Simplified: count operations
        // Real implementation would track function boundaries
        50 // Placeholder
    }

    fn has_external_calls_near_selector(&self, _selector: u32) -> bool {
        self.bytecode.iter().any(|&b| b == 0xf1 || b == 0xf4)
    }

    fn has_arithmetic_near_selector(&self, _selector: u32) -> bool {
        self.bytecode.iter().any(|&b| b == 0x01 || b == 0x02 || b == 0x03)
    }

    fn has_overflow_checks(&self) -> bool {
        // Check for LT/GT after arithmetic
        self.bytecode.windows(2).any(|w| matches!(w, [0x01, 0x10] | [0x02, 0x10]))
    }

    fn has_state_changes(&self, _selector: u32) -> bool {
        self.bytecode.contains(&0x55) // SSTORE present
    }

    fn has_price_calculations(&self, _selector: u32) -> bool {
        // Check for MUL/DIV operations
        self.bytecode.iter().any(|&b| b == 0x02 || b == 0x04)
    }

    fn has_validation_before(&self, location: usize) -> bool {
        if location < 20 {
            return false;
        }
        // Check for ISZERO + REVERT pattern before location
        self.bytecode[location.saturating_sub(20)..location]
            .windows(2)
            .any(|w| w == &[0x15, 0xfd])
    }

    fn has_validation_after(&self, location: usize) -> bool {
        let end = (location + 20).min(self.bytecode.len());
        self.bytecode[location..end]
            .windows(2)
            .any(|w| w == &[0x15, 0xfd])
    }

    fn has_input_validation(&self) -> bool {
        // Check for CALLDATALOAD followed by checks
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x35 {
                let next_5 = &self.bytecode[i+1..i+6];
                if next_5.iter().any(|&b| b == 0x10 || b == 0x11 || b == 0x14) {
                    return true;
                }
            }
        }
        false
    }

    pub fn get_high_risk_entry_points(&self) -> Vec<EntryPoint> {
        self.identify_entry_points()
            .into_iter()
            .filter(|e| matches!(e.access_control, AccessLevel::Public) && e.complexity > 50)
            .collect()
    }

    pub fn get_critical_attack_vectors(&self) -> Vec<AttackVector> {
        let surface = self.map_attack_surface();
        surface.attack_vectors
            .into_iter()
            .filter(|v| matches!(v.impact, SecuritySeverity::Critical) && v.exploitability > 0.7)
            .collect()
    }
}
