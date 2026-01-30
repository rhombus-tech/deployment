use crate::bytecode::SecurityFinding;

pub struct ChainlinkVrfDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkVrfDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_vrf_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Chainlink VRF randomness can be manipulated or predicted at PC {}. \
                    Missing proper fulfillment validation allows biased random outcomes.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_vrf_callback_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "VRF callback function lacks reentrancy protection at PC {}. \
                    Attacker can manipulate state during random number fulfillment.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });}

        if let Some(pc) = self.detect_vrf_subscription_dos() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "VRF subscription vulnerable to DOS attack at PC {}. \
                    Insufficient funding checks can brick randomness requests.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_vrf_manipulation(&self) -> Option<usize> {
        // Look for VRF usage without proper request validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // requestRandomWords, rawFulfillRandomWords selectors
                if matches!(selector, [0x9e, 0x31, _, _] | [0x1f, 0xe5, 0x43, 0xe3]) {
                    let mut validates_request_id = false;
                    let mut checks_coordinator = false;
                    let mut stores_request_params = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for request ID validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (requestId)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (stored request)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ (validating match)
                                validates_request_id = true;
                            }
                        }
                        // Check for VRF coordinator validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (coordinator address)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                checks_coordinator = true;
                            }
                        }
                        // Check if storing request parameters
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (params)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x20 && // KECCAK256
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x55 { // SSTORE
                                stores_request_params = true;
                            }
                        }
                    }
                    
                    if !validates_request_id || !checks_coordinator {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_vrf_callback_exploit(&self) -> Option<usize> {
        // Look for fulfillRandomWords without reentrancy protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // fulfillRandomWords selector
                if matches!(selector, [0x1f, 0xe5, 0x43, 0xe3]) {
                    let mut has_reentrancy_guard = false;
                    let mut makes_external_call = false;
                    let mut updates_critical_state = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for reentrancy guard
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (guard)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x55 { // SSTORE (setting guard)
                                has_reentrancy_guard = true;
                            }
                        }
                        // Check for external calls
                        if self.bytecode[j] == 0xf1 || // CALL
                           self.bytecode[j] == 0xf4 { // DELEGATECALL
                            makes_external_call = true;
                        }
                        // Check if updating critical state (winner selection, payouts)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (random value)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x55 { // SSTORE (storing winner)
                                updates_critical_state = true;
                            }
                        }
                    }
                    
                    if makes_external_call && updates_critical_state && !has_reentrancy_guard {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_vrf_subscription_dos(&self) -> Option<usize> {
        // Look for VRF requests without subscription balance checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // requestRandomWords selector
                if matches!(selector, [0x9e, 0x31, _, _]) {
                    let mut checks_subscription = false;
                    let mut validates_gas_limit = false;
                    let mut has_fallback = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for subscription balance validation
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getSubscription selector
                            if matches!(sub_selector, [0xa2, 0x1e, _, _]) {
                                checks_subscription = true;
                            }
                        }
                        // Check for gas limit validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (gas limit)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking max)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                validates_gas_limit = true;
                            }
                        }
                        // Check for fallback mechanism
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x57 && // JUMPI (conditional)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 { // SLOAD (fallback source)
                                has_fallback = true;
                            }
                        }
                    }
                    
                    if !checks_subscription || !validates_gas_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
