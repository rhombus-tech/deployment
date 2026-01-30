use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterfaceConfusionVulnerability {
    WrongInterfaceCast { description: String, location: usize, confidence: f32 },
    MissingInterfaceCheck { description: String, location: usize },
    InterfaceIdMismatch { description: String, location: usize },
}

pub struct InterfaceConfusionDetector {
    bytecode: Vec<u8>,
}

impl InterfaceConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<InterfaceConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // supportsInterface selector (ERC165): 0x01ffc9a7
        let supports_interface = [0x01, 0xff, 0xc9, 0xa7];
        
        // Check for external calls without interface validation
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.is_external_call(i) {
                if !self.has_interface_check(i, i + 80) {
                    vulnerabilities.push(InterfaceConfusionVulnerability::MissingInterfaceCheck {
                        description: "External call without ERC165 interface check - wrong interface risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_external_call(&self, location: usize) -> bool {
        matches!(self.bytecode.get(location), Some(&0xF1) | Some(&0xFA) | Some(&0xF4))
    }
    
    fn has_interface_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let supports_interface = [0x01, 0xff, 0xc9, 0xa7];
        self.bytecode[start..range_end].windows(4).any(|w| w == supports_interface)
    }
}
