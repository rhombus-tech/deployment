pub struct FoundryTomlSecurityIssueDetector {
    bytecode: Vec<u8>,
}

impl FoundryTomlSecurityIssueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_insecure_foundry_config() {
            findings.push("Foundry config: Insecure configuration in foundry.toml".to_string());
        }

        if self.has_exposed_rpc_urls() {
            findings.push("Foundry config: RPC URLs exposed in foundry.toml".to_string());
        }

        if self.has_unsafe_compiler_settings() {
            findings.push("Foundry config: Unsafe compiler settings in Foundry configuration".to_string());
        }

        findings
    }

    fn has_insecure_foundry_config(&self) -> bool {
        // Check for Foundry config patterns with security issues
        let foundry_patterns = [b"foundry", b"Foundry", b".toml"];
        let has_foundry = foundry_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_foundry {
            // Look for insecure settings
            let insecure_patterns = [
                b"optimizer = false",
                b"fuzz_runs = 1",
                b"via_ir = false",
            ];
            
            for pattern in &insecure_patterns {
                if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_exposed_rpc_urls(&self) -> bool {
        // Check for RPC URLs in Foundry config
        let has_foundry = self.bytecode.windows(7).any(|w| w == b"foundry" || w == b".toml");
        
        if has_foundry {
            // Look for RPC URL patterns
            let rpc_patterns = [
                b"rpc_url",
                b"eth_rpc_url",
                b"https://",
                b"wss://",
            ];
            
            for pattern in &rpc_patterns {
                if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                    // Check if URL contains sensitive info (API keys)
                    let has_sensitive = self.bytecode.windows(6).any(|w| 
                        w == b"apikey" || w == b"apiKey" || w == b"token="
                    );
                    
                    if has_sensitive {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn has_unsafe_compiler_settings(&self) -> bool {
        // Check for unsafe compiler configurations
        let has_foundry = self.bytecode.windows(7).any(|w| w == b"foundry");
        
        if has_foundry {
            // Look for dangerous settings
            let unsafe_settings = [
                b"unchecked_math",
                b"allow_paths = [\"/\"]"  // Overly permissive
            ];
            
            for setting in &unsafe_settings {
                if self.bytecode.windows(setting.len()).any(|w| w == *setting) {
                    return true;
                }
            }
            
            // Check for very low optimizer runs (< 200)
            for i in 0..self.bytecode.len().saturating_sub(15) {
                if self.bytecode[i..].windows(13).any(|w| w == b"optimizer_runs") {
                    // Look for small numbers nearby
                    if i + 20 < self.bytecode.len() {
                        let following = &self.bytecode[i+13..i+20];
                        // Check for patterns like "= 1" or "= 10"
                        if following.windows(3).any(|w| w == b"= 1" || w == b"= 2") {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
}
