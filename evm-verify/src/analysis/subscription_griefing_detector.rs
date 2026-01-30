use crate::bytecode::SecurityFinding;

pub struct SubscriptionGriefingDetector {
    bytecode: Vec<u8>,
}

impl SubscriptionGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_forced_renewal() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Subscription can be forcefully renewed without user consent at PC {}. \
                    Users can be griefed by malicious renewals charging unauthorized payments.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_cancellation_griefing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Subscription cancellation can be blocked or delayed indefinitely at PC {}. \
                    Users cannot exit subscriptions, enabling fund extraction.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_arbitrary_price_change() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Subscription price can be changed arbitrarily without user approval at PC {}. \
                    Provider can charge excessive fees for existing subscriptions.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        findings
    }

    fn detect_forced_renewal(&self) -> Option<usize> {
        // Look for renewal functions callable by non-subscriber
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // renew, renewSubscription, processRenewal selectors
                if matches!(selector, [0x6a, 0x4e, _, _] | [0x7c, 0x5f, _, _] | [0x8e, 0x7d, _, _]) {
                    let mut has_subscriber_check = false;
                    let mut has_approval_check = false;
                    let mut charges_payment = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for subscriber authorization (only subscriber can renew)
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (subscriber address)
                               j + 2 < self.bytecode.len() && self.bytecode[j + 2] == 0x33 && // CALLER
                               j + 3 < self.bytecode.len() && self.bytecode[j + 3] == 0x14 { // EQ
                                has_subscriber_check = true;
                            }
                        }
                        // Check for renewal approval flag
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check if loading auto-renew approval flag
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x15 { // ISZERO (checking if approved)
                                        has_approval_check = true;
                                    }
                                }
                            }
                        }
                        // Check for payment charging
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transferFrom, chargePayment selectors
                            if matches!(sub_selector, [0x23, 0xb8, 0x72, 0xdd] | [0x9a, 0x4f, _, _]) {
                                charges_payment = true;
                            }
                        }
                    }
                    
                    if charges_payment && !has_subscriber_check && !has_approval_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cancellation_griefing(&self) -> Option<usize> {
        // Look for cancel functions with blocking mechanisms
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // cancel, cancelSubscription, unsubscribe selectors
                if matches!(selector, [0x40, 0xe5, 0x8c, 0xd5] | [0x7c, 0x4d, _, _] | [0x8e, 0x5f, _, _]) {
                    let mut has_admin_gate = false;
                    let mut has_arbitrary_condition = false;
                    let mut has_time_lock = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for admin-only cancellation
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // onlyOwner, onlyAdmin checks
                            if matches!(sub_selector, [0x8d, 0xa5, 0xcb, 0x5b] | [0xa2, 0x3f, _, _]) {
                                has_admin_gate = true;
                            }
                        }
                        // Check for external condition that can block cancellation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0xfa || self.bytecode[j] == 0xf1 { // STATICCALL or CALL
                                // Check if return value gates cancellation
                                for k in j..j + 8 {
                                    if self.bytecode[k] == 0x15 && // ISZERO
                                       k + 1 < self.bytecode.len() && self.bytecode[k + 1] == 0x57 { // JUMPI (revert if false)
                                        has_arbitrary_condition = true;
                                    }
                                }
                            }
                        }
                        // Check for unbounded time lock on cancellation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (unlock time)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (checking if before unlock)
                                // Check if unlock time can be set arbitrarily high
                                has_time_lock = true;
                            }
                        }
                    }
                    
                    if has_admin_gate || has_arbitrary_condition || has_time_lock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_arbitrary_price_change(&self) -> Option<usize> {
        // Look for price update functions without subscriber protections
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setPrice, updatePrice, changeSubscriptionFee selectors
                if matches!(selector, [0x91, 0xb7, 0xf5, 0xed] | [0x8d, 0x4c, _, _] | [0x9e, 0x6f, _, _]) {
                    let mut has_governance_delay = false;
                    let mut has_price_cap = false;
                    let mut has_opt_out_mechanism = false;
                    let mut modifies_price = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for governance/timelock delay on price changes
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (proposal timestamp)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_governance_delay = true;
                            }
                        }
                        // Check for maximum price increase cap
                        if j + 10 < self.bytecode.len() {
                            let mut loads_old_price = false;
                            let mut calculates_ratio = false;
                            let mut compares_limit = false;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x54 { // SLOAD (old price)
                                    loads_old_price = true;
                                }
                                if self.bytecode[k] == 0x04 { // DIV (ratio calculation)
                                    calculates_ratio = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    compares_limit = true;
                                }
                            }
                            if loads_old_price && calculates_ratio && compares_limit {
                                has_price_cap = true;
                            }
                        }
                        // Check for opt-out/cancellation mechanism triggered by price increase
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // notifyPriceChange, allowCancellation selectors
                            if matches!(sub_selector, [0xa1, 0x3e, _, _] | [0xb3, 0x4f, _, _]) {
                                has_opt_out_mechanism = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (storing new price)
                            modifies_price = true;
                        }
                    }
                    
                    if modifies_price && !has_governance_delay && !has_price_cap && !has_opt_out_mechanism {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
