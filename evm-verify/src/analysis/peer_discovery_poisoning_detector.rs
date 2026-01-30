pub struct PeerDiscoveryPoisoningDetector {
    bytecode: Vec<u8>,
}

impl PeerDiscoveryPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unverified_peer_discovery() {
            findings.push("Peer discovery poisoning: Unverified peer discovery mechanism".to_string());
        }

        if self.lacks_peer_reputation_system() {
            findings.push("Peer discovery poisoning: Missing peer reputation validation".to_string());
        }

        if self.has_malicious_peer_injection() {
            findings.push("Peer discovery poisoning: Vulnerable to malicious peer injection".to_string());
        }

        findings
    }

    fn has_unverified_peer_discovery(&self) -> bool {
        // Check for peer discovery without verification
        let discovery_patterns = [b"discover", b"bootstrap", b"peers"];
        let has_discovery = discovery_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_discovery {
            // Look for verification mechanisms
            let verification_patterns = [b"verify", b"validate", b"authenticate", b"signature"];
            let has_verification = verification_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_verification;
        }
        
        false
    }

    fn lacks_peer_reputation_system(&self) -> bool {
        // Check for peer management without reputation tracking
        let has_peer = self.bytecode.windows(4).any(|w| w == b"peer");
        
        if has_peer {
            // Look for reputation/scoring patterns
            let reputation_patterns = [
                b"reputation",
                b"score",
                b"trust",
                b"rating",
            ];
            
            let has_reputation = reputation_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_reputation;
        }
        
        false
    }

    fn has_malicious_peer_injection(&self) -> bool {
        // Check for peer addition without validation
        let addition_patterns = [b"addPeer", b"add_peer", b"newPeer"];
        let has_addition = addition_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_addition {
            // Look for security checks before adding peers
            // Check for CALLER verification (access control)
            let mut has_access_control = false;
            for i in 0..self.bytecode.len().saturating_sub(5) {
                if self.bytecode[i] == 0x33 { // CALLER
                    // Check for EQ comparison nearby
                    if self.bytecode[i..i+5].iter().any(|&b| b == 0x14) {
                        has_access_control = true;
                        break;
                    }
                }
            }
            
            return !has_access_control;
        }
        
        false
    }
}
