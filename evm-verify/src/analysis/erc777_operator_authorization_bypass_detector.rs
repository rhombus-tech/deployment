pub struct Erc777OperatorAuthorizationBypassDetector {
    bytecode: Vec<u8>,
}

impl Erc777OperatorAuthorizationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_operator_bypass() {
            findings.push("ERC777: Operator authorization can be bypassed".to_string());
        }

        if self.has_unauthorized_operator_calls() {
            findings.push("ERC777: Unauthorized operator calls possible".to_string());
        }

        if self.has_hook_reentrancy() {
            findings.push("ERC777: ERC777 hooks vulnerable to reentrancy attacks".to_string());
        }

        findings
    }

    fn has_operator_bypass(&self) -> bool {
        let operator_patterns = [b"operator", b"Operator", b"authorizeOperator"];
        let has_operator = operator_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_operator {
            // Check for proper authorization checks (EQ opcode checking caller)
            let mut has_auth_check = false;
            for i in 0..self.bytecode.len().saturating_sub(5) {
                if self.bytecode[i] == 0x33 { // CALLER
                    if self.bytecode[i..i+5].iter().any(|&b| b == 0x14) { // EQ
                        has_auth_check = true;
                        break;
                    }
                }
            }
            
            return !has_auth_check;
        }
        
        false
    }

    fn has_unauthorized_operator_calls(&self) -> bool {
        let erc777_patterns = [b"operatorSend", b"operatorBurn", b"tokensReceived"];
        let has_erc777_ops = erc777_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_erc777_ops {
            // Look for isOperatorFor checks
            let has_check = self.bytecode.windows(12).any(|w| w == b"isOperatorFor");
            return !has_check;
        }
        
        false
    }

    fn has_hook_reentrancy(&self) -> bool {
        let hook_patterns = [b"tokensReceived", b"tokensToSend"];
        let has_hooks = hook_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_hooks {
            // Check for external calls in hooks
            let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xf4).count();
            
            // Check for reentrancy guard
            let has_guard = self.bytecode.windows(10).any(|w| w == b"nonReentra" || w == b"ReentrancyG");
            
            return call_count > 1 && !has_guard;
        }
        
        false
    }
}
