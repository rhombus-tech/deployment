use crate::bytecode::SecurityFinding;

pub struct SubscriptionPaymentManipulationDetector {
    bytecode: Vec<u8>,
}

impl SubscriptionPaymentManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_payment_frontrunning() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Subscription payment vulnerable to frontrunning at PC {}. \
                    Payment amounts can be manipulated before processing.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_billing_cycle_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Billing cycle timing can be manipulated at PC {}. \
                    Subscribers can delay or skip payment periods.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_overpayment_no_refund() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Overpayments not refunded properly at PC {}. \
                    Excess payments are not returned to subscribers.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_payment_frontrunning(&self) -> Option<usize> {
        // Look for payment processing without commit-reveal or similar protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // processPayment, chargeSubscription selectors
                if matches!(selector, [0x7a, 0x4e, _, _] | [0x8c, 0x5f, _, _]) {
                    let mut has_commit_reveal = false;
                    let mut uses_spot_price = false;
                    let mut has_slippage_protection = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for commit-reveal pattern
                        if j + 10 < self.bytecode.len() {
                            let mut has_commit = false;
                            let mut has_reveal = false;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x54 { // SLOAD (commitment)
                                    has_commit = true;
                                }
                                if self.bytecode[k] == 0x14 { // EQ (reveal verification)
                                    has_reveal = true;
                                }
                            }
                            if has_commit && has_reveal {
                                has_commit_reveal = true;
                            }
                        }
                        // Check for spot price usage (vulnerable to manipulation)
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getPrice, getCurrentPrice selectors (spot price)
                            if matches!(sub_selector, [0x98, 0xd5, 0xfd, 0xca] | [0xa1, 0x2f, _, _]) {
                                uses_spot_price = true;
                            }
                        }
                        // Check for slippage protection (min/max bounds)
                        if j + 6 < self.bytecode.len() {
                            let mut has_comparison = false;
                            for k in j..j + 6 {
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    has_comparison = true;
                                }
                            }
                            if has_comparison {
                                has_slippage_protection = true;
                            }
                        }
                    }
                    
                    if uses_spot_price && !has_commit_reveal && !has_slippage_protection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_billing_cycle_manipulation(&self) -> Option<usize> {
        // Look for billing cycle calculations vulnerable to timestamp manipulation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // calculateNextBilling, isPaymentDue selectors
                if matches!(selector, [0x6a, 0x3e, _, _] | [0x7c, 0x4f, _, _]) {
                    let mut uses_timestamp = false;
                    let mut has_block_anchor = false;
                    let mut vulnerable_to_delay = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for TIMESTAMP usage in billing calculation
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 { // TIMESTAMP
                                uses_timestamp = true;
                                // Check if used in modulo operation (periodic billing)
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x06 { // MOD
                                        vulnerable_to_delay = true;
                                    }
                                }
                            }
                        }
                        // Check for block number anchoring (more reliable)
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x43 { // NUMBER
                                has_block_anchor = true;
                            }
                        }
                    }
                    
                    if uses_timestamp && vulnerable_to_delay && !has_block_anchor {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_overpayment_no_refund(&self) -> Option<usize> {
        // Look for payment functions without overpayment refund logic
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // pay, processPayment, chargeSubscription selectors
                if matches!(selector, [0x1b, 0x9c, 0xe2, 0x0d] | [0x7a, 0x4e, _, _] | [0x8c, 0x5f, _, _]) {
                    let mut accepts_payment = false;
                    let mut calculates_difference = false;
                    let mut refunds_excess = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for payment acceptance
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transferFrom, pull payment selectors
                            if matches!(sub_selector, [0x23, 0xb8, 0x72, 0xdd]) {
                                accepts_payment = true;
                            }
                        }
                        // Check for difference calculation (paid - required)
                        if j + 8 < self.bytecode.len() {
                            let mut has_subtraction = false;
                            let mut compares_amounts = false;
                            for k in j..j + 8 {
                                if self.bytecode[k] == 0x03 { // SUB (calculating overpayment)
                                    has_subtraction = true;
                                }
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                    compares_amounts = true;
                                }
                            }
                            if has_subtraction && compares_amounts {
                                calculates_difference = true;
                            }
                        }
                        // Check for refund call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transfer (refund), safeTransfer selectors
                            if matches!(sub_selector, [0xa9, 0x05, 0x9c, 0xbb] | [0x42, 0x84, 0x2e, 0x0e]) {
                                refunds_excess = true;
                            }
                        }
                    }
                    
                    if accepts_payment && !calculates_difference && !refunds_excess {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
