use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletAddressVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HardwareWalletAddressVerificationBypassDetector {
    bytecode: Vec<u8>,
}

impl HardwareWalletAddressVerificationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HardwareWalletAddressVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_address_substitution_attack());
        vulnerabilities.extend(self.detect_display_spoofing());
        vulnerabilities.extend(self.detect_blind_signing_vulnerability());

        vulnerabilities
    }

    fn detect_address_substitution_attack(&self) -> Vec<HardwareWalletAddressVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (transaction execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_address_parameter = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_address_parameter {
                    let validates_address_on_device = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let requires_manual_verification = window.iter().any(|&b| b == 0x42); // TIMESTAMP (wait for user)
                    
                    if !validates_address_on_device {
                        vulns.push(HardwareWalletAddressVulnerability {
                            pc,
                            vulnerability_type: "AddressSubstitutionAttack".to_string(),
                            description: format!(
                                "Transaction recipient at PC {} vulnerable to address substitution. Attack: compromised computer/browser shows different recipient address than \
                                actually sent to hardware wallet, if user doesn't verify address on device screen, funds sent to attacker. Attack flow: (1) user initiates send to \
                                0xALICE on infected computer, (2) malware substitutes recipient with 0xATTACKER in transaction, (3) hardware wallet signs transaction to 0xATTACKER, (4) \
                                computer UI still shows 0xALICE, user thinks transfer succeeded correctly, (5) funds stolen. Variants: clipboard hijacking (malware monitors clipboard, \
                                replaces copied addresses), browser extension attack (injects malicious address), MITM on USB communication. Example: user copies withdrawal address from \
                                exchange, malware replaces clipboard with attacker's address, user pastes and signs without verifying on Ledger screen. Real attacks: >$1M stolen via \
                                clipboard malware. Missing: mandatory address verification on device, address checksum validation, warning for first-time recipients. Should enforce: always \
                                display full recipient address on hardware wallet screen, require user to confirm address matches, show address checksum, implement address book on device \
                                (trusted addresses), warn if sending to new/unusual address.",
                                pc
                            ),
                            confidence: 0.91,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_display_spoofing(&self) -> Vec<HardwareWalletAddressVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (transaction parameters)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_amount_transfer = window.iter().any(|&b| b == 0x03); // SUB
                
                if has_amount_transfer {
                    let displays_full_details = window.iter().filter(|&&b| b == 0x35).count() >= 4;
                    let validates_displayed_data = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !displays_full_details {
                        vulns.push(HardwareWalletAddressVulnerability {
                            pc,
                            vulnerability_type: "DisplaySpoofing".to_string(),
                            description: format!(
                                "Transaction display at PC {} may not show all critical details on hardware wallet. Attack: hardware wallet has limited screen, can't display all \
                                transaction details, malware hides critical info. Display attacks: (1) show amount but hide contract interaction (approve vs transfer), (2) truncate \
                                long addresses (show 0x1234...5678 hiding middle), (3) hide gas price (user approves with 10000 gwei thinking it's 10 gwei), (4) don't display data \
                                field (hide malicious contract call). Example: user approves token spending on Ledger, screen shows 'Approve 100 USDC', doesn't show it's actually \
                                unlimited approval (2^256-1). Or: device shows 'Send 1 ETH' but doesn't show it's calling malicious contract that will drain more. Display limitations: \
                                small screen can't fit full 42-char address, complex transactions need multiple clicks to review. Missing: comprehensive transaction summary, forced \
                                display of critical params, pagination for complex data. Should display: full address (paginated if needed), exact amount in human-readable format, \
                                destination contract vs EOA, function being called, approval amounts, gas price/limit, warning for unusual params.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_blind_signing_vulnerability(&self) -> Vec<HardwareWalletAddressVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (message hash)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_data = window.iter().any(|&b| b == 0x37); // CALLDATACOPY
                
                if has_message_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let decodes_message_on_device = forward.iter().filter(|&&b| b == 0x35).count() >= 3;
                    let displays_human_readable = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !decodes_message_on_device {
                        vulns.push(HardwareWalletAddressVulnerability {
                            pc,
                            vulnerability_type: "BlindSigningVulnerability".to_string(),
                            description: format!(
                                "Message signing at PC {} enables blind signing without content display. Attack: hardware wallet signs message hash without showing actual message \
                                content, user signs malicious message unknowingly. Blind signing risks: (1) EIP-712 structured data shown as hash only, user can't verify fields, (2) \
                                raw data (bytes) shown as hex, user can't read content, (3) long messages truncated, hidden parts contain malicious instructions. Example: phishing site \
                                requests signature on 'message' via personal_sign, Ledger shows 'Sign message hash: 0x1234...', user approves, actually signed message: 'Transfer all \
                                assets to 0xATTACKER'. Or: EIP-712 Permit shown as domain separator hash + typehash, user can't see they're approving unlimited token spending. Especially \
                                dangerous: off-chain signatures (Permit, vote delegation) execute without additional confirmation. Missing: on-device message decoding, EIP-712 field display, \
                                human-readable formatting. Should implement: decode and display EIP-712 fields on device (owner, spender, amount, etc.), show full message text for \
                                personal_sign (with UTF-8 decoding), warn user about blind signing risks, require explicit opt-in for raw hash signing.",
                                pc
                            ),
                            confidence: 0.87,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
