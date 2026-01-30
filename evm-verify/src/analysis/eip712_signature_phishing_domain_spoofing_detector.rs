use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712PhishingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Eip712SignaturePhishingDomainSpoofingDetector {
    bytecode: Vec<u8>,
}

impl Eip712SignaturePhishingDomainSpoofingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Eip712PhishingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_domain_separator_validation());
        vulnerabilities.extend(self.detect_typehash_manipulation());
        vulnerabilities.extend(self.detect_verifying_contract_mismatch());

        vulnerabilities
    }

    fn detect_missing_domain_separator_validation(&self) -> Vec<Eip712PhishingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (EIP-712 hash)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_data = window.iter().filter(|&&b| b == 0x35).count() >= 3;
                
                if has_signature_data {
                    let validates_domain_separator = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let checks_chain_id = window.iter().any(|&b| b == 0x46); // CHAINID
                    let verifies_contract_address = window.iter().any(|&b| b == 0x30); // ADDRESS
                    
                    if !validates_domain_separator || !checks_chain_id {
                        vulns.push(Eip712PhishingVulnerability {
                            pc,
                            vulnerability_type: "MissingDomainSeparatorValidation".to_string(),
                            description: format!(
                                "EIP-712 signature verification at PC {} missing domain separator validation. Attack: EIP-712 structured data signing includes domain separator \
                                (name, version, chainId, verifyingContract) to prevent cross-domain replay, if not validated, phishing site tricks users into signing malicious data. \
                                Phishing flow: (1) user visits fake dApp lookalike (uniswap.scam vs uniswap.org), (2) fake site requests EIP-712 signature with malicious domain, (3) \
                                signature valid on real contract because domain not checked, (4) attacker uses signature to drain funds. Example: user signs 'Permit' message on fake \
                                site with domain name='Uniswap V3' (vs real 'Uniswap V2'), signature still valid if contract doesn't verify domain name. Or: chainId set to different \
                                network, user signs on testnet, signature replayed on mainnet. Missing: domain separator reconstruction and comparison, chain ID validation, contract \
                                address verification. Should implement: reconstructedDomain = keccak256(abi.encode(TYPEHASH, name, version, chainId, address(this))), require(domain == \
                                reconstructedDomain), revert if mismatch.",
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

    fn detect_typehash_manipulation(&self) -> Vec<Eip712PhishingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ECRECOVER (signature verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_message_hash {
                    let validates_typehash = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_hardcoded_typehash = window.iter().filter(|&&b| matches!(b, 0x60..=0x7F)).count() >= 4;
                    
                    if !validates_typehash {
                        vulns.push(Eip712PhishingVulnerability {
                            pc,
                            vulnerability_type: "TypehashManipulation".to_string(),
                            description: format!(
                                "EIP-712 typehash at PC {} not validated, allowing phishing via type substitution. Attack: EIP-712 message types defined by TYPEHASH = keccak256(string), \
                                if contract doesn't validate typehash matches expected type, phisher crafts message with different type that hashes to same value or tricks user into \
                                signing wrong type. Example: legitimate Permit type: 'Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)', phisher creates \
                                type: 'Transfer(address to,uint256 amount)' and gets user to sign, if contract accepts any typehash, attacker's signature validates. Or: homograph attack in \
                                type string (use unicode lookalikes), user sees 'Transfer' but actually signs 'Transf‌er' (with zero-width character). Missing: strict typehash validation, \
                                type string verification, signature purpose indication to user. Should implement: bytes32 constant PERMIT_TYPEHASH = keccak256('Permit(...)'); require(typehash \
                                == PERMIT_TYPEHASH), display actual type string to user in wallet, not just hash.",
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

    fn detect_verifying_contract_mismatch(&self) -> Vec<Eip712PhishingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x30 { // ADDRESS (contract address check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_signature_verification = window.iter().any(|&b| b == 0x01); // ECRECOVER
                
                if has_signature_verification {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let validates_verifying_contract = window.iter().any(|&b| b == 0x14); // EQ
                    let checks_in_domain_separator = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !validates_verifying_contract {
                        vulns.push(Eip712PhishingVulnerability {
                            pc,
                            vulnerability_type: "VerifyingContractMismatch".to_string(),
                            description: format!(
                                "Signature verification at PC {} doesn't validate verifyingContract field. Attack: EIP-712 domain includes verifyingContract=address(this) to bind \
                                signature to specific contract, if not validated, signature intended for different contract can be replayed. Phishing: (1) attacker deploys malicious \
                                contract at address B mimicking real contract A, (2) tricks user into signing EIP-712 message for contract B, (3) uses signature on real contract A if \
                                verifyingContract not checked. Example: user signs Permit for malicious token at 0xBAD..., attacker replays signature on real token at 0xGOOD... if real \
                                token doesn't validate verifyingContract field in domain. Or: user signs on L2, attacker replays on L1 if contracts at same address on both chains. Missing: \
                                require verifyingContract == address(this) in domain separator validation, cross-chain replay protection. Should enforce: domain.verifyingContract must equal \
                                address(this), include chainId check, reject signatures from different contract addresses even if other params match.",
                                pc
                            ),
                            confidence: 0.88,
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
