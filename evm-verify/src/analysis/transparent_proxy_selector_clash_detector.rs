use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransparentProxySelectorClashVulnerability {
    SelectorCollision { description: String, location: usize, selector: Vec<u8>, confidence: f32 },
    AdminFunctionCollision { description: String, location: usize },
    ImplementationFunctionClash { description: String, location: usize },
}

pub struct TransparentProxySelectorClashDetector {
    bytecode: Vec<u8>,
}

impl TransparentProxySelectorClashDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TransparentProxySelectorClashVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Transparent proxy has admin functions that must not clash with implementation
        let admin_selectors = self.find_admin_selectors();
        let implementation_selectors = self.find_implementation_selectors();
        
        for admin_sel in &admin_selectors {
            for impl_sel in &implementation_selectors {
                if admin_sel == impl_sel {
                    vulnerabilities.push(TransparentProxySelectorClashVulnerability::SelectorCollision {
                        description: format!("Function selector {:?} collision between admin and implementation", admin_sel),
                        location: 0,
                        selector: admin_sel.to_vec(),
                        confidence: 0.95,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_admin_selectors(&self) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        
        // Common admin function selectors
        let known_admin = [
            [0x38, 0x93, 0xd1, 0xa0], // changeAdmin
            [0xf8, 0x51, 0xa4, 0x40], // admin
            [0x35, 0x59, 0xc2, 0x96], // implementation
            [0x4f, 0x1e, 0xf2, 0x86], // upgradeToAndCall
        ];
        
        for sel in known_admin {
            if self.bytecode.windows(4).any(|w| w == sel) {
                selectors.push(sel);
            }
        }
        
        selectors
    }
    
    fn find_implementation_selectors(&self) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        
        // Extract selectors from dispatcher
        for i in 0..self.bytecode.len().saturating_sub(6) {
            // Pattern: PUSH4 selector, EQ
            if self.bytecode[i] == 0x63 { // PUSH4
                if i + 5 < self.bytecode.len() {
                    let selector = [
                        self.bytecode[i+1],
                        self.bytecode[i+2],
                        self.bytecode[i+3],
                        self.bytecode[i+4],
                    ];
                    selectors.push(selector);
                }
            }
        }
        
        selectors
    }
}
