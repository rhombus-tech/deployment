use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7579ModuleConflictDetectorVulnerability {
    ModuleConflict { description: String, location: usize },
}
pub struct Erc7579ModuleConflictDetector { bytecode: Vec<u8> }
impl Erc7579ModuleConflictDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7579ModuleConflictDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        let delegatecall_count = self.bytecode.iter().filter(|&&b| b == 0xf4).count();
        if delegatecall_count >= 2 {
            vulnerabilities.push(Erc7579ModuleConflictDetectorVulnerability::ModuleConflict {
                description: "Multiple DELEGATECALL - module conflict risk".to_string(), location: 0,
            });
        }
        vulnerabilities
    }
}