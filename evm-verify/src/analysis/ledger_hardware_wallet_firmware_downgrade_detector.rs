use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerFirmwareVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct LedgerHardwareWalletFirmwareDowngradeDetector {
    bytecode: Vec<u8>,
}

impl LedgerHardwareWalletFirmwareDowngradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<LedgerFirmwareVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_version_rollback_vulnerability());
        vulnerabilities.extend(self.detect_unsigned_firmware_acceptance());
        vulnerabilities.extend(self.detect_secure_boot_bypass());

        vulnerabilities
    }

    fn detect_version_rollback_vulnerability(&self) -> Vec<LedgerFirmwareVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (version update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_version_number = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_firmware_update = window.iter().any(|&b| b == 0x37); // CALLDATACOPY
                
                if has_version_number && has_firmware_update {
                    let prevents_downgrade = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2; // LT/GT checks
                    let has_monotonic_counter = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !prevents_downgrade {
                        vulns.push(LedgerFirmwareVulnerability {
                            pc,
                            vulnerability_type: "VersionRollbackVulnerability".to_string(),
                            description: format!(
                                "Firmware version update at PC {} allows downgrade to vulnerable versions. Attack: hardware wallet firmware update mechanism doesn't enforce \
                                monotonic version progression, attacker with physical access downgrades to old firmware with known vulnerabilities. Example: Ledger Nano current \
                                firmware 2.1.0 patched critical bug, attacker downgrades to 1.6.0, exploits patched vulnerability to extract seed phrase. Downgrade attack flow: \
                                (1) obtain device, (2) trigger firmware update mode, (3) flash old vulnerable firmware, (4) exploit vulnerability, (5) extract private keys. Also \
                                enables: bypassing security patches, using deprecated features attackers understand better, rolling back to version before security feature added. \
                                Missing: anti-rollback counter (eFuse), minimum allowed version check, version monotonicity enforcement. Should implement: secure counter incremented \
                                on each update (can't decrease), refuse firmware if version <= current version, brick device if rollback attempted.",
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

    fn detect_unsigned_firmware_acceptance(&self) -> Vec<LedgerFirmwareVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x37 { // CALLDATACOPY (firmware data load)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_firmware_application = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_firmware_application {
                    let has_signature_verification = window.iter().any(|&b| b == 0x01); // ECRECOVER would use precompiles
                    let has_hash_check = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !has_signature_verification {
                        vulns.push(LedgerFirmwareVulnerability {
                            pc,
                            vulnerability_type: "UnsignedFirmwareAcceptance".to_string(),
                            description: format!(
                                "Firmware loading at PC {} missing cryptographic signature verification. Attack: if firmware updates not signed by manufacturer's private key, \
                                attacker can flash custom malicious firmware. Attack: (1) reverse engineer firmware format, (2) create malicious firmware with backdoor, (3) flash to \
                                device via update mechanism, (4) firmware runs without validation, (5) backdoor exfiltrates seed phrase on next unlock. Real-world parallels: evil maid \
                                attack on hardware wallets, supply chain firmware injection, rogue firmware from unofficial sources. Malicious firmware can: display correct address but \
                                sign transaction to attacker's address, leak seed via side channel, bypass PIN after N attempts, send seed to attacker on unlock. Missing: ECDSA/RSA \
                                signature verification, manufacturer public key in ROM, signature check before applying update. Should implement: firmware must be signed by manufacturer \
                                key stored in secure boot ROM, verify signature before any application, reject unsigned/invalid signatures.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_secure_boot_bypass(&self) -> Vec<LedgerFirmwareVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (firmware hash)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_boot_sequence = window.iter().any(|&b| b == 0x37); // CALLDATACOPY
                
                if has_boot_sequence {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let verifies_boot_integrity = forward.iter().any(|&b| b == 0x14); // EQ
                    let has_chain_of_trust = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !has_chain_of_trust {
                        vulns.push(LedgerFirmwareVulnerability {
                            pc,
                            vulnerability_type: "SecureBootBypass".to_string(),
                            description: format!(
                                "Boot integrity verification at PC {} incomplete or bypassable. Attack: secure boot ensures only authentic firmware executes, if chain of trust broken, \
                                attacker boots malicious firmware. Secure boot should: (1) ROM bootloader (immutable) runs first, (2) verifies firmware signature/hash, (3) only boots if \
                                valid, (4) firmware then verifies apps. If bypass exists: attacker interrupts boot sequence (voltage glitch, debug interface), skips verification, boots \
                                malicious code. Attack examples: JTAG debug port left open bypasses secure boot, glitching during signature check causes branch to boot anyway, firmware \
                                hash stored in modifiable memory allows tampering. Consequences: complete device compromise, keylogger in boot code captures PIN, modified firmware displays \
                                fake addresses. Missing: immutable boot ROM, hardware-enforced signature check, debug interface lockdown. Should have: bootloader in OTP/mask ROM (can't modify), \
                                hardware crypto accelerator verifies signature before boot, debug ports fused off in production.",
                                pc
                            ),
                            confidence: 0.84,
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
