use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5643SubscriptionNftVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5643SubscriptionNftDetector {
    bytecode: Vec<u8>,
}

impl Erc5643SubscriptionNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5643SubscriptionNftVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5643 defines subscription NFTs with expiration
        // Detect subscription bypass
        if let Some(location) = self.has_subscription_bypass() {
            vulnerabilities.push(Erc5643SubscriptionNftVulnerability {
                vulnerability_type: "ERC-5643 Subscription Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "NFT functionality accessible with expired subscription. Expiration timestamp not validated before granting access. Check expiresAt() > block.timestamp for all gated features.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect renewal manipulation
        if let Some(location) = self.has_renewal_manipulation() {
            vulnerabilities.push(Erc5643SubscriptionNftVulnerability {
                vulnerability_type: "ERC-5643 Subscription Renewal Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "renewSubscription() allows arbitrary expiration extension without payment validation. Users could extend subscriptions indefinitely. Enforce payment and duration limits.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect cancellation abuse
        if let Some(location) = self.has_cancellation_abuse() {
            vulnerabilities.push(Erc5643SubscriptionNftVulnerability {
                vulnerability_type: "ERC-5643 Subscription Cancellation Abuse".to_string(),
                location,
                severity: "Medium".to_string(),
                description: "cancelSubscription() allows immediate cancellation without pro-rata refund logic. Users lose remaining subscription time. Implement partial refund mechanism.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect transfer with subscription retention
        if let Some(location) = self.has_transfer_subscription_retention() {
            vulnerabilities.push(Erc5643SubscriptionNftVulnerability {
                vulnerability_type: "ERC-5643 Transfer Subscription Retention".to_string(),
                location,
                severity: "High".to_string(),
                description: "NFT transfer retains subscription without validation. Subscriptions should either transfer with NFT or be cleared. Implement clear subscription transfer policy.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_subscription_bypass(&self) -> Option<usize> {
        // Pattern: Function execution without subscription expiration check
        // Look for critical operations without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for restricted operation (e.g., CALL or state change)
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0x55 { // CALL or SSTORE
                // Check if subscription expiration is validated before
                let mut has_expiration_check = false;
                
                for j in i.saturating_sub(30)..i {
                    // Look for SLOAD (reading expiration) + TIMESTAMP comparison
                    if self.bytecode[j] == 0x54 { // SLOAD (expiration time)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x42 { // TIMESTAMP
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 || self.bytecode[m] == 0x11 { // LT/GT
                                        has_expiration_check = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !has_expiration_check {
                    // Verify this looks like gated functionality
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (tokenId)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_renewal_manipulation(&self) -> Option<usize> {
        // Pattern: Subscription renewal (SSTORE expiration) without payment check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (updating expiration)
                // Check for payment validation (CALLVALUE or token transfer)
                let mut has_payment_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for CALLVALUE (ETH payment)
                    if self.bytecode[j] == 0x34 { // CALLVALUE
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // Amount validation
                                has_payment_check = true;
                                break;
                            }
                        }
                    }
                    // Or token transfer (CALL/STATICCALL to ERC20)
                    if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xfa {
                        has_payment_check = true;
                    }
                }
                
                if !has_payment_check {
                    // Verify this is expiration update (adds time to current)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x01 { // ADD (extending duration)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_cancellation_abuse(&self) -> Option<usize> {
        // Pattern: Cancellation (SSTORE zero) without refund logic
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (canceling subscription)
                // Check if setting expiration to zero or past time
                let mut is_cancellation = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x60 { // PUSH1
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0 {
                            is_cancellation = true;
                        }
                    }
                    if self.bytecode[j] == 0x42 { // TIMESTAMP (setting to current = immediate cancel)
                        is_cancellation = true;
                    }
                }
                
                if is_cancellation {
                    // Check for refund logic (CALL for transfer)
                    let mut has_refund = false;
                    for j in i+1..i+40.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 { // CALL (refund transfer)
                            has_refund = true;
                            break;
                        }
                    }
                    if !has_refund {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_transfer_subscription_retention(&self) -> Option<usize> {
        // Pattern: NFT transfer without subscription handling
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (owner change)
                // Check if this is a transfer (from/to addresses involved)
                let mut is_transfer = false;
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x35 { // CALLDATALOAD (from/to)
                        is_transfer = true;
                    }
                }
                
                if is_transfer {
                    // Check if subscription is handled (cleared or transferred)
                    let mut has_subscription_handling = false;
                    
                    for j in i+1..i+30.min(self.bytecode.len()) {
                        // Look for expiration SSTORE (handling subscription)
                        if self.bytecode[j] == 0x55 { // Additional SSTORE for subscription
                            has_subscription_handling = true;
                            break;
                        }
                    }
                    
                    if !has_subscription_handling {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
