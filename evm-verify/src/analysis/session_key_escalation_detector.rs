use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionKeyEscalationDetectorVulnerability {
    PrivilegeEscalation { description: String, location: usize },
}
pub struct SessionKeyEscalationDetector { bytecode: Vec<u8> }
impl SessionKeyEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SessionKeyEscalationDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (expiry check)
                let has_permission_check = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .iter().filter(|&&b| b == 0x54).count() >= 2;
                if !has_permission_check {
                    vulnerabilities.push(SessionKeyEscalationDetectorVulnerability::PrivilegeEscalation {
                        description: "Session key without permission boundaries".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}