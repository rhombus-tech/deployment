use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BiconomySessionKeyVulnerability {
    SessionKeyRevocationBypass,
    SpendingLimitManipulation,
    TimeBasedConstraintBypass,
    SessionKeyReplay,
    PermissionEscalation,
    BatchSessionAbuse,
    SessionKeyRotation,
    ModuleCompatibilityRisk,
    ValidUntilManipulation,
    ValidAfterBypass,
}

pub struct BiconomySessionKeyDetector {
    bytecode: Vec<u8>,
}

impl BiconomySessionKeyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BiconomySessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_time_validation() {
            vulnerabilities.push(BiconomySessionKeyVulnerability::TimeBasedConstraintBypass);
        }
        vulnerabilities
    }

    fn has_time_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x42 && w[1] == 0x11)
    }
}
