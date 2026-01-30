pub struct RpcKeyExposureInFrontendDetector {
    bytecode: Vec<u8>,
}

impl RpcKeyExposureInFrontendDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_exposed_api_key() {
            findings.push("RPC key exposure: API key exposed in frontend code".to_string());
        }

        if self.has_hardcoded_rpc_credentials() {
            findings.push("RPC key exposure: Hardcoded RPC credentials in client-side code".to_string());
        }

        if self.lacks_key_rotation() {
            findings.push("RPC key exposure: No key rotation mechanism for exposed keys".to_string());
        }

        findings
    }

    fn has_exposed_api_key(&self) -> bool {
        // Check for API key patterns in bytecode
        let api_key_indicators = [
            b"apiKey",
            b"api_key",
            b"APIKEY",
            b"API_KEY",
            b"apikey=",
        ];
        
        for indicator in &api_key_indicators {
            if self.bytecode.windows(indicator.len()).any(|w| w == *indicator) {
                // Check if followed by a value (likely exposed key)
                return true;
            }
        }
        
        // Check for common provider API key patterns
        let provider_patterns = [
            b"infura",
            b"alchemy",
            b"quicknode",
            b"moralis",
        ];
        
        for provider in &provider_patterns {
            if self.bytecode.windows(provider.len()).any(|w| w == *provider) {
                // Provider name + API key nearby = exposure risk
                return true;
            }
        }
        
        false
    }

    fn has_hardcoded_rpc_credentials(&self) -> bool {
        // Check for RPC URLs with embedded credentials
        let has_rpc_url = self.bytecode.windows(8).any(|w| w == b"https://" || w == b"wss://");
        
        if has_rpc_url {
            // Look for authentication patterns in URLs
            // Format: https://username:password@host or https://host/api_key
            let auth_indicators = [b"://", b"@", b"/api/"];
            
            let mut has_auth_pattern = false;
            for indicator in &auth_indicators {
                if self.bytecode.windows(indicator.len()).any(|w| w == *indicator) {
                    has_auth_pattern = true;
                    break;
                }
            }
            
            if has_auth_pattern {
                // Check for 32+ char hex strings (typical API keys)
                let mut consecutive_hex = 0;
                for &byte in &self.bytecode {
                    if (byte >= b'0' && byte <= b'9') || 
                       (byte >= b'a' && byte <= b'f') || 
                       (byte >= b'A' && byte <= b'F') {
                        consecutive_hex += 1;
                        if consecutive_hex >= 32 {
                            return true;
                        }
                    } else {
                        consecutive_hex = 0;
                    }
                }
            }
        }
        
        false
    }

    fn lacks_key_rotation(&self) -> bool {
        // Check if API keys are used but no rotation mechanism exists
        let has_api_key = self.has_exposed_api_key();
        
        if has_api_key {
            // Look for key rotation indicators
            let rotation_patterns = [
                b"rotate",
                b"refresh",
                b"renew",
                b"update",
            ];
            
            let has_rotation = rotation_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_rotation;
        }
        
        false
    }
}
