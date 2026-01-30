use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountAbstractionVulnerability {
    UserOperationValidation,
    PaymasterIntegration,
    EntryPointInteraction,
    NonceManagement,
    SignatureValidation,
}

pub struct AccountAbstractionDetector {
    bytecode: Vec<u8>,
}

impl AccountAbstractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AccountAbstractionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Simple bytecode pattern matching for ERC-4337 patterns
        if self.has_validate_userop() {
            vulnerabilities.push(AccountAbstractionVulnerability::UserOperationValidation);
        }
        if self.has_paymaster_logic() {
            vulnerabilities.push(AccountAbstractionVulnerability::PaymasterIntegration);
        }
        if self.has_entrypoint_calls() {
            vulnerabilities.push(AccountAbstractionVulnerability::EntryPointInteraction);
        }
        
        vulnerabilities
    }
    
    fn has_validate_userop(&self) -> bool {
        // Look for validateUserOp function signature 0x3a871cdd
        self.bytecode.windows(4).any(|w| w == [0x3a, 0x87, 0x1c, 0xdd])
    }
    
    fn has_paymaster_logic(&self) -> bool {
        // Look for paymaster-related patterns
        self.bytecode.windows(4).any(|w| w[0] == 0xf4 && w[1] == 0x65) // STATICCALL patterns
    }
    
    fn has_entrypoint_calls(&self) -> bool {
        // Look for entry point interactions
        self.bytecode.windows(2).any(|w| w[0] == 0xf1) // CALL opcode
    }
}
