use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnstructuredStorageCollisionVulnerability {
    Eip1967SlotCollision {
        description: String,
        colliding_slot: String,
        location: usize,
    },
    UnstructuredSlotOverlap {
        description: String,
        slot_a: String,
        slot_b: String,
        location: usize,
    },
    WeakRandomSlot {
        description: String,
        location: usize,
        slot_calculation: String,
    },
}

pub struct UnstructuredStorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl UnstructuredStorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UnstructuredStorageCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let eip1967_slots = vec![
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", // implementation
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", // admin  
            "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3", // beacon
        ];
        
        let unstructured_slots = self.find_unstructured_slots();
        
        for slot in &unstructured_slots {
            for eip_slot in &eip1967_slots {
                if self.slots_may_collide(slot, eip_slot) {
                    vulnerabilities.push(UnstructuredStorageCollisionVulnerability::Eip1967SlotCollision {
                        description: format!("Unstructured slot may collide with EIP-1967 slot"),
                        colliding_slot: eip_slot.to_string(),
                        location: 0,
                    });
                }
            }
        }
        
        for i in 0..unstructured_slots.len() {
            for j in i+1..unstructured_slots.len() {
                if self.slots_may_collide(&unstructured_slots[i], &unstructured_slots[j]) {
                    vulnerabilities.push(UnstructuredStorageCollisionVulnerability::UnstructuredSlotOverlap {
                        description: "Two unstructured storage slots may overlap".to_string(),
                        slot_a: unstructured_slots[i].clone(),
                        slot_b: unstructured_slots[j].clone(),
                        location: 0,
                    });
                }
            }
        }
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_weak_slot_calculation(i) {
                vulnerabilities.push(UnstructuredStorageCollisionVulnerability::WeakRandomSlot {
                    description: "Weak unstructured storage slot calculation detected".to_string(),
                    location: i,
                    slot_calculation: "keccak256(simple_value)".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_unstructured_slots(&self) -> Vec<String> {
        let mut slots = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x20 { // SHA3/KECCAK256
                if i > 10 {
                    let has_string_before = self.bytecode[i-10..i].iter().any(|&b| b >= 0x60 && b <= 0x7f);
                    if has_string_before {
                        slots.push(format!("keccak_slot_at_{}", i));
                    }
                }
            }
        }
        
        slots
    }
    
    fn slots_may_collide(&self, _slot_a: &str, _slot_b: &str) -> bool {
        false
    }
    
    fn is_weak_slot_calculation(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20].windows(3).any(|w| {
            w[0] == 0x60 && w[1] < 10 && w[2] == 0x20
        })
    }
}
