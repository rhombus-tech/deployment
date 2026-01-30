use crate::bytecode::opcodes::*;

pub struct FakeTokenAirdropDetector {
    bytecode: Vec<u8>,
}

impl FakeTokenAirdropDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_airdrop_claim_function()
            && (self.has_phishing_approval() || self.has_honeypot_pattern())
    }

    fn has_airdrop_claim_function(&self) -> bool {
        // Common airdrop function selectors
        self.has_claim_selector() || self.has_mint_selector()
    }

    fn has_claim_selector(&self) -> bool {
        // claim(), claimTokens(), claimAirdrop() selectors
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+4];
                // Common claim selectors: 0x4e71d92d (claim), 0x48c54b9d (claimTokens)
                if (selector[0] == 0x4e && selector[1] == 0x71)
                    || (selector[0] == 0x48 && selector[1] == 0xc5) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_mint_selector(&self) -> bool {
        // mint() selector: 0xa0712d68
        self.bytecode.windows(4).any(|w| {
            w[0] == PUSH4 && w[1] == 0xa0 && w[2] == 0x71
        })
    }

    fn has_phishing_approval(&self) -> bool {
        // Claim requires approve first (phishing pattern)
        self.has_claim_selector() && self.has_approval_requirement()
    }

    fn has_approval_requirement(&self) -> bool {
        // Check for approval check before claim
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            if self.is_allowance_check(i) {
                // Followed by REVERT if no approval
                for j in i+1..i.min(self.bytecode.len()).min(i+20) {
                    if self.bytecode[j] == REVERT {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_allowance_check(&self, pos: usize) -> bool {
        // allowance() selector: 0xdd62ed3e
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0xdd
            && self.bytecode[pos+2] == 0x62
    }

    fn has_honeypot_pattern(&self) -> bool {
        // Can claim but cannot transfer out
        self.has_transfer_restriction()
            || self.has_blacklist_on_transfer()
            || self.has_owner_only_transfer()
    }

    fn has_transfer_restriction(&self) -> bool {
        // Transfer always reverts for non-owner
        let mut found_transfer = false;
        let mut has_revert_path = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            // transfer selector
            if opcode == PUSH4 && i + 4 < self.bytecode.len() {
                if self.bytecode[i+1] == 0xa9 && self.bytecode[i+2] == 0x05 {
                    found_transfer = true;
                }
            }
            // Revert after transfer check
            if found_transfer && opcode == REVERT {
                has_revert_path = true;
            }
        }

        found_transfer && has_revert_path
    }

    fn has_blacklist_on_transfer(&self) -> bool {
        // SLOAD (blacklist check) before transfer
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.is_transfer_selector(i) {
                // Look back for SLOAD (blacklist check)
                if i >= 15 {
                    for j in (i.saturating_sub(15))..i {
                        if self.bytecode[j] == SLOAD {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_owner_only_transfer(&self) -> bool {
        // Transfer requires CALLER == owner
        let mut has_transfer = false;
        let mut has_caller_check = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if self.is_transfer_selector(i) {
                has_transfer = true;
            }
            if opcode == CALLER && has_transfer {
                has_caller_check = true;
            }
        }

        has_transfer && has_caller_check
    }

    fn is_transfer_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0xa9
            && self.bytecode[pos+2] == 0x05
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_airdrop_detection() {
        let bytecode = vec![
            PUSH4, 0x4e, 0x71, 0xd9, 0x2d,    // claim selector
            PUSH4, 0xdd, 0x62, 0xed, 0x3e,    // allowance check
            ISZERO,
            PUSH1, 0x08,
            JUMPI,
            REVERT,                            // Revert if no approval
            JUMPDEST,
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,    // transfer
            CALLER, EQ,                        // Only owner can transfer
            ISZERO,
            PUSH1, 0x08,
            JUMPI,
            REVERT,
        ];
        let detector = FakeTokenAirdropDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_legitimate_airdrop() {
        let bytecode = vec![
            PUSH4, 0x4e, 0x71, 0xd9, 0x2d,    // claim
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,    // transfer (no restrictions)
            CALL,
        ];
        let detector = FakeTokenAirdropDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
