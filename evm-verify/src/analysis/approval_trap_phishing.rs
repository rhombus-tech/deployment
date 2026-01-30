/// Approval Trap / Phishing Contract Exploits
/// 
/// Coverage: Social engineering smart contracts ($100M+ annual phishing losses)
/// Attacks: Unlimited approvals, fake tokens, approval chaining, permit phishing

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTrapVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub trap_pattern: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct ApprovalTrapPhishingDetector {
    bytecode: Vec<u8>,
}

impl ApprovalTrapPhishingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ApprovalTrapVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Unlimited Approval Trap
        if self.detect_unlimited_approval_trap() {
            vulnerabilities.push(ApprovalTrapVulnerability {
                vulnerability_type: "Unlimited Approval Trap".to_string(),
                severity: "Critical".to_string(),
                trap_pattern: "Contract requests unlimited token approval".to_string(),
                description: "Malicious contract tricks users into approving unlimited token spending".to_string(),
                exploit_scenario: "User visits fake 'airdrop claim' site\nSite: 'Approve our contract to claim 1000 FREE tokens!'\nUser signs: approve(maliciousContract, type(uint256).max)\nContract claims: 'Claim button' → actually does nothing\nAttacker later:\n1. Calls transferFrom(user, attacker, ALL_TOKENS)\n2. Drains user's entire USDC balance ($50k)\nUser approved unlimited spending for fake airdrop".to_string(),
                remediation: "Warn on unlimited approvals, recommend exact amounts, approval scanning tools, revoke trackers".to_string(),
            });
        }
        
        // 2. Fake Token Mimicry
        if self.detect_fake_token_mimicry() {
            vulnerabilities.push(ApprovalTrapVulnerability {
                vulnerability_type: "Fake Token Contract Phishing".to_string(),
                severity: "High".to_string(),
                trap_pattern: "Token contract mimics legitimate token".to_string(),
                description: "Fake token contract with identical name/symbol to legitimate token tricks users".to_string(),
                exploit_scenario: "Real USDC: 0xA0b8...c0de (6 decimals)\nFake USDC: 0xA0b9...c0de (18 decimals) ← 1 character different\nAttacker lists fake USDC on DEX aggregator\nUser: 'Swap 1 ETH for USDC'\nAggregator shows: 'Best rate: 3000 USDC' (fake)\nUser receives 3000 fake USDC (worth $0)\nReal rate was 3.0 USDC per ETH\nUser lost 1 ETH ($3000)".to_string(),
                remediation: "Address verification, token registry whitelist, visual address verification, rugcheck integration".to_string(),
            });
        }
        
        // 3. Permit Signature Phishing (EIP-2612)
        if self.detect_permit_phishing() {
            vulnerabilities.push(ApprovalTrapVulnerability {
                vulnerability_type: "EIP-2612 Permit Signature Phishing".to_string(),
                severity: "Critical".to_string(),
                trap_pattern: "Malicious permit signature request".to_string(),
                description: "Attacker tricks user into signing gasless approval that steals all tokens".to_string(),
                exploit_scenario: "User on phishing site: 'Sign to verify wallet'\nSite requests EIP-712 signature:\n  'permit(spender=0xAttacker, amount=UINT256_MAX)'\nUser: 'Just a verification signature, no gas cost!'\nUser signs permit\nAttacker immediately:\n1. Calls contract.permit() with user's signature\n2. Approval granted without user transaction\n3. Calls transferFrom(), drains $100k USDC\nGasless approval = invisible theft".to_string(),
                remediation: "Signature content warnings, permit amount limits, time-bounded permits, hardware wallet verification".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_unlimited_approval_trap(&self) -> bool {
        // Approval request with max uint256
        self.bytecode.windows(40).any(|w| {
            // Look for approve() function with PUSH max value pattern
            w.contains(&0x60) && // PUSH (likely max value)
            w.contains(&0xFF) && // Marker of max value
            w.contains(&0x55)    // SSTORE (approval storage)
        })
    }
    
    fn detect_fake_token_mimicry(&self) -> bool {
        // ERC-20 implementation without proper registry
        self.bytecode.windows(30).any(|w| {
            w.contains(&0x18) && // XOR (symbol manipulation)
            w.contains(&0x06) && // MOD (decimal manipulation)
            w.contains(&0x55)    // SSTORE (token data)
        })
    }
    
    fn detect_permit_phishing(&self) -> bool {
        // EIP-2612 permit without proper validation
        self.bytecode.windows(50).any(|w| {
            w.contains(&0x1C) && // SHR (signature recovery)
            w.contains(&0x01) && // ECRECOVER vicinity
            w.contains(&0x55) && // SSTORE (approval)
            !w.contains(&0x42)   // No TIMESTAMP (no deadline check)
        })
    }
}
