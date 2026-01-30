use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainMemoInjectionVulnerability {
    pub location: usize,
    pub injection_type: MemoInjectionType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoInjectionType {
    UnsanitizedMemoField,            // Memo field not sanitized
    MemoCommandInjection,            // Commands injected via memo
    CrossChainReentrancy,            // Reentrancy via memo callback
    MemoParserExploit,               // Parser vulnerability in memo
    ArbitraryCallViaMemo,            // Arbitrary call encoded in memo
    MemoDataOverflow,                // Buffer overflow in memo handling
}

pub struct CrossChainMemoInjectionDetector {
    bytecode: Vec<u8>,
}

impl CrossChainMemoInjectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainMemoInjectionVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_unsanitized_memo() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::UnsanitizedMemoField,
                severity: "Critical".to_string(),
                description: "Cross-chain memo field used without sanitization. ThorChain $8M exploit: \
                             attacker injected malicious memo to trigger unintended transfers. Memo MUST \
                             be validated before use.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_memo_command_injection() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::MemoCommandInjection,
                severity: "Critical".to_string(),
                description: "Memo field parsed as commands without validation. Allows attacker to inject \
                             arbitrary instructions via cross-chain messages.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_cross_chain_reentrancy() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::CrossChainReentrancy,
                severity: "High".to_string(),
                description: "Memo callback enables cross-chain reentrancy. External call based on memo \
                             data before state finalization allows reentrancy attacks.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_memo_parser_exploit() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::MemoParserExploit,
                severity: "High".to_string(),
                description: "Memo parsing logic vulnerable to malformed input. Does not validate memo \
                             structure before parsing, enabling parser exploits.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_arbitrary_call_via_memo() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::ArbitraryCallViaMemo,
                severity: "Critical".to_string(),
                description: "Memo encodes arbitrary call target and data. Allows attacker to call any \
                             contract with any parameters via cross-chain bridge message.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_memo_data_overflow() {
            vulnerabilities.push(CrossChainMemoInjectionVulnerability {
                location: loc,
                injection_type: MemoInjectionType::MemoDataOverflow,
                severity: "High".to_string(),
                description: "Memo data length not validated, enabling buffer overflow. Can overwrite \
                             adjacent memory or cause transaction revert DoS.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_unsanitized_memo(&self) -> Option<usize> {
        // CALLDATALOAD for memo without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check if used in CALL or DELEGATECALL without sanitization
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xf4 { // CALL or DELEGATECALL
                        // Check for validation between CALLDATALOAD and CALL
                        let mut has_validation = false;
                        for k in i..j {
                            if matches!(self.bytecode[k], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                                has_validation = true;
                                break;
                            }
                        }
                        if !has_validation {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_memo_command_injection(&self) -> Option<usize> {
        // Memo parsing with string operations
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Bridge message handlers
                if selector == 0x3e5beab9 || selector == 0x8d9e5d3c { // handleMessage, processMemo
                    // Check for string parsing (BYTE operations on calldata)
                    let mut has_byte_ops = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x1a { // BYTE
                            has_byte_ops = true;
                            break;
                        }
                    }
                    
                    if has_byte_ops {
                        // Check for command whitelist
                        let mut has_whitelist = false;
                        for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                            if self.bytecode[j] == 0x14 { // EQ (comparing to allowed commands)
                                has_whitelist = true;
                                break;
                            }
                        }
                        if !has_whitelist {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_cross_chain_reentrancy(&self) -> Option<usize> {
        // External call with memo data before SSTORE
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (memo)
                for j in i + 1..std::cmp::min(i + 35, self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 { // CALL
                        // Check if SSTORE happens after CALL
                        for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 { // SSTORE after CALL
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_memo_parser_exploit(&self) -> Option<usize> {
        // CALLDATASIZE check missing before memo processing
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check for CALLDATASIZE validation
                let mut has_size_check = false;
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x36 { // CALLDATASIZE
                        has_size_check = true;
                        break;
                    }
                }
                
                if !has_size_check {
                    // Check if this is used in parsing context
                    for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                        if self.bytecode[j] == 0x1a { // BYTE (parsing)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_arbitrary_call_via_memo(&self) -> Option<usize> {
        // CALL with target from calldata
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if call target comes from CALLDATALOAD
                let mut target_from_calldata = false;
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x35 { // CALLDATALOAD
                        target_from_calldata = true;
                        break;
                    }
                }
                
                if target_from_calldata {
                    // Check for whitelist of allowed targets
                    let mut has_whitelist = false;
                    for j in i.saturating_sub(25)..i {
                        if self.bytecode[j] == 0x14 { // EQ (whitelist check)
                            has_whitelist = true;
                            break;
                        }
                    }
                    if !has_whitelist {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_memo_data_overflow(&self) -> Option<usize> {
        // CALLDATACOPY without length validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x37 { // CALLDATACOPY
                // Check for length limit before copy
                let mut has_length_check = false;
                for j in i.saturating_sub(15)..i {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        has_length_check = true;
                        break;
                    }
                }
                if !has_length_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
