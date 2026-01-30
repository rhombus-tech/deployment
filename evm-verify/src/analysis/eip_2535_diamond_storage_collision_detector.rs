use crate::bytecode::opcodes::*;

pub struct Eip2535DiamondStorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl Eip2535DiamondStorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_diamond_pattern()
            && self.has_storage_collision_risk()
    }

    fn has_diamond_pattern(&self) -> bool {
        // DELEGATECALL indicating proxy/diamond pattern
        self.has_delegatecall() && self.has_facet_management()
    }

    fn has_delegatecall(&self) -> bool {
        self.bytecode.iter().any(|&op| op == DELEGATECALL)
    }

    fn has_facet_management(&self) -> bool {
        // Multiple function selectors and routing logic
        self.has_function_routing() && self.has_multiple_implementations()
    }

    fn has_function_routing(&self) -> bool {
        // CALLDATALOAD followed by conditional jumps
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                let mut has_eq = false;
                let mut has_jumpi = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if self.bytecode[j] == EQ { has_eq = true; }
                    if self.bytecode[j] == JUMPI { has_jumpi = true; }
                }

                if has_eq && has_jumpi {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_multiple_implementations(&self) -> bool {
        // Multiple DELEGATECALL operations
        let delegatecall_count = self.bytecode.iter()
            .filter(|&&op| op == DELEGATECALL)
            .count();
        
        delegatecall_count >= 2
    }

    fn has_storage_collision_risk(&self) -> bool {
        // Direct storage access without namespacing
        self.has_direct_storage_access() && !self.has_storage_namespacing()
    }

    fn has_direct_storage_access(&self) -> bool {
        // SLOAD/SSTORE with simple slot calculations
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == PUSH1 || self.bytecode[i] == PUSH2 {
                // Simple slot number followed by SLOAD/SSTORE
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if self.bytecode[j] == SLOAD || self.bytecode[j] == SSTORE {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_storage_namespacing(&self) -> bool {
        // KECCAK256 for storage slot calculation (EIP-2535 pattern)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == KECCAK256 {
                // Check if followed by SLOAD/SSTORE
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == SLOAD || self.bytecode[j] == SSTORE {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_collision() {
        let bytecode = vec![
            CALLDATALOAD, EQ, JUMPI, // Function routing
            DELEGATECALL,            // Facet 1
            DELEGATECALL,            // Facet 2
            PUSH1, 0x01, SSTORE,     // Direct storage (collision risk)
        ];
        let detector = Eip2535DiamondStorageCollisionDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_diamond() {
        let bytecode = vec![
            CALLDATALOAD, EQ, JUMPI,
            DELEGATECALL,
            DELEGATECALL,
            KECCAK256, SSTORE,       // Namespaced storage
        ];
        let detector = Eip2535DiamondStorageCollisionDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
