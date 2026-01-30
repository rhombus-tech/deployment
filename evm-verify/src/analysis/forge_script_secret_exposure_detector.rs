pub struct ForgeScriptSecretExposureDetector {
    bytecode: Vec<u8>,
}

impl ForgeScriptSecretExposureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_exposed_env_variable() {
            findings.push("Forge script: Environment variable exposed in deployment script".to_string());
        }

        if self.has_private_key_in_script() {
            findings.push("Forge script: Private key found in forge script bytecode".to_string());
        }

        if self.has_rpc_url_with_credentials() {
            findings.push("Forge script: RPC URL with credentials exposed in script".to_string());
        }

        findings
    }

    fn has_exposed_env_variable(&self) -> bool {
        // Check for environment variable access patterns
        let env_patterns = [
            b"PRIVATE_KEY",
            b"MNEMONIC",
            b"SECRET",
            b"API_KEY",
            b"RPC_URL",
            b"INFURA",
            b"ALCHEMY",
        ];
        
        for pattern in &env_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        // Check for vm.envString, vm.envUint patterns (Forge cheatcodes)
        let forge_patterns = [b"envString", b"envUint", b"envAddress"];
        for pattern in &forge_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_private_key_in_script(&self) -> bool {
        // Check for PUSH32 with high-entropy data (potential private key)
        for i in 0..self.bytecode.len().saturating_sub(33) {
            if self.bytecode[i] == 0x7f { // PUSH32
                let key_data = &self.bytecode[i+1..i+33];
                
                // Check for non-zero, non-padding data
                let has_data = key_data.iter().any(|&b| b != 0x00);
                let not_all_ff = key_data.iter().any(|&b| b != 0xff);
                
                if has_data && not_all_ff {
                    // Check for vm.sign, vm.broadcast nearby (Forge script indicators)
                    if self.check_forge_signing_nearby(i) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_rpc_url_with_credentials(&self) -> bool {
        // Check for RPC URL patterns with embedded credentials
        let rpc_patterns = [
            b"http://",
            b"https://",
            b"wss://",
            b"ws://",
        ];
        
        for pattern in &rpc_patterns {
            for window in self.bytecode.windows(pattern.len()) {
                if window == *pattern {
                    // Check if followed by credentials pattern (user:pass@)
                    let start_pos = window.as_ptr() as usize - self.bytecode.as_ptr() as usize;
                    if start_pos + pattern.len() + 10 < self.bytecode.len() {
                        let following = &self.bytecode[start_pos + pattern.len()..start_pos + pattern.len() + 20];
                        if following.windows(3).any(|w| w == b":" || w == b"@") {
                            return true;
                        }
                    }
                }
            }
        }
        
        // Check for API key in URL patterns
        let api_key_patterns = [b"apikey=", b"api_key=", b"token="];
        for pattern in &api_key_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
    
    fn check_forge_signing_nearby(&self, pos: usize) -> bool {
        let search_range = 50;
        let start = pos.saturating_sub(search_range);
        let end = (pos + search_range).min(self.bytecode.len());
        
        let forge_indicators = [b"sign", b"broadcast", b"startBroadcast"];
        let search_window = &self.bytecode[start..end];
        
        for indicator in &forge_indicators {
            if search_window.windows(indicator.len()).any(|w| w == *indicator) {
                return true;
            }
        }
        false
    }
}
