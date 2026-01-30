pub struct HardhatConfigSecretLeakDetector {
    bytecode: Vec<u8>,
}

impl HardhatConfigSecretLeakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_exposed_hardhat_secrets() {
            findings.push("Hardhat config: Secrets exposed in hardhat.config.js/ts".to_string());
        }

        if self.has_private_key_in_config() {
            findings.push("Hardhat config: Private key found in configuration file".to_string());
        }

        if self.has_api_key_exposure() {
            findings.push("Hardhat config: API keys exposed in Hardhat configuration".to_string());
        }

        findings
    }

    fn has_exposed_hardhat_secrets(&self) -> bool {
        // Check for Hardhat-specific secret patterns
        let hardhat_patterns = [b"hardhat", b"Hardhat", b"HARDHAT"];
        let has_hardhat = hardhat_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_hardhat {
            // Look for secret/key patterns nearby
            let secret_patterns = [b"secret", b"private", b"key", b"mnemonic"];
            let has_secrets = secret_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return has_secrets;
        }
        
        false
    }

    fn has_private_key_in_config(&self) -> bool {
        // Check for private key patterns in config files
        let config_patterns = [b"config", b".js", b".ts"];
        let has_config = config_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_config {
            // Look for 64-character hex strings (private keys)
            let mut consecutive_hex = 0;
            for &byte in &self.bytecode {
                if (byte >= b'0' && byte <= b'9') || 
                   (byte >= b'a' && byte <= b'f') || 
                   (byte >= b'A' && byte <= b'F') {
                    consecutive_hex += 1;
                    if consecutive_hex >= 64 {
                        return true;
                    }
                } else {
                    consecutive_hex = 0;
                }
            }
            
            // Also check for 0x prefix followed by hex
            for i in 0..self.bytecode.len().saturating_sub(66) {
                if self.bytecode[i] == b'0' && self.bytecode[i+1] == b'x' {
                    let hex_part = &self.bytecode[i+2..i+66];
                    if hex_part.iter().all(|&b| 
                        (b >= b'0' && b <= b'9') || 
                        (b >= b'a' && b <= b'f') || 
                        (b >= b'A' && b <= b'F')
                    ) {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn has_api_key_exposure(&self) -> bool {
        // Check for API keys in Hardhat configuration
        let has_hardhat = self.bytecode.windows(7).any(|w| w == b"hardhat");
        
        if has_hardhat {
            // Look for common API key providers
            let provider_patterns = [
                b"etherscan",
                b"infura",
                b"alchemy",
                b"apiKey",
            ];
            
            for provider in &provider_patterns {
                if self.bytecode.windows(provider.len()).any(|w| w == *provider) {
                    return true;
                }
            }
        }
        
        false
    }
}
