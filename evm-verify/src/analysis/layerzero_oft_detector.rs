/// LayerZero OFT/ONFT Vulnerability Detector
///
/// Detects vulnerabilities specific to LayerZero's Omnichain Fungible Token (OFT)
/// and Omnichain Non-Fungible Token (ONFT) standards.
///
/// Real-world context:
/// - $6B+ TVL across LayerZero bridges
/// - Used by Stargate, Radiant, ApeCoin, etc.
/// - Attack surface: Trusted relayer manipulation, executor bypass, compose calls
/// - Risk: Cross-chain message manipulation can drain multiple chains simultaneously

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroOftVulnerability {
    pub vulnerability_type: LayerZeroOftVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayerZeroOftVulnerabilityType {
    TrustedRelayerBypass,           // Relayer can be bypassed/manipulated
    ExecutorManipulation,           // Executor address not validated
    ComposeCallReentrancy,          // lzCompose callback reentrancy
    CrossChainNonceDesync,          // Nonce tracking broken across chains
    AdapterParamsExploit,           // AdapterParams manipulated for gas griefing
    UntrustedRemoteBypass,          // setTrustedRemote bypassed
    OFTMintingExploit,              // Unauthorized minting on destination chain
    PayloadSizeMismatch,            // Payload validation missing
    RefundAddressManipulation,      // Refund sent to attacker
    InboundNonceSkip,               // Inbound nonce can be skipped
}

pub struct LayerZeroOftDetector {
    bytecode: Vec<u8>,
}

impl LayerZeroOftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LayerZeroOftVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Trusted relayer bypass
        if let Some(vuln) = self.detect_trusted_relayer_bypass() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Compose call reentrancy
        if let Some(vuln) = self.detect_compose_call_reentrancy() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Adapter params exploit
        if let Some(vuln) = self.detect_adapter_params_exploit() {
            vulnerabilities.push(vuln);
        }
        
        // 4. OFT minting exploit
        if let Some(vuln) = self.detect_oft_minting_exploit() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Payload validation missing
        if let Some(vuln) = self.detect_payload_validation_missing() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_trusted_relayer_bypass(&self) -> Option<LayerZeroOftVulnerability> {
        // LayerZero uses trusted relayers - must validate message source
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for message reception
            let mut receives_message = false;
            let mut validates_source = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Message reception (external call)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                    receives_message = true;
                }
                
                // Source validation (checking sender/relayer)
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        validates_source = true;
                    }
                }
            }
            
            if receives_message && !validates_source {
                return Some(LayerZeroOftVulnerability {
                    vulnerability_type: LayerZeroOftVulnerabilityType::TrustedRelayerBypass,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "LayerZero message received without validating trusted source. \
                                Attacker can send fake cross-chain messages to mint unlimited tokens.".to_string(),
                    exploit_scenario: "1. OFT contract on Ethereum expects messages from trusted relayer\n\
                                      2. No validation that msg.sender == trustedRemote\n\
                                      3. Attacker directly calls lzReceive() on Ethereum\n\
                                      4. Fakes message claiming 1M tokens sent from Arbitrum\n\
                                      5. Ethereum contract mints 1M tokens to attacker\n\
                                      6. No tokens actually locked on Arbitrum\n\
                                      7. Attacker sells 1M tokens, crashes market\n\
                                      8. $50M+ stolen if large OFT exploited\n\
                                      9. Similar to Nomad bridge $190M exploit pattern".to_string(),
                    recommendation: "Validate trusted source: require(msg.sender == trustedRemote[srcChain]). \
                                  Use LayerZero's lzReceive() with proper validation. Verify srcChainId \
                                  and srcAddress. Implement nonReentrant. Add message hash verification. \
                                  Reference: LayerZero OFT standard implementation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_compose_call_reentrancy(&self) -> Option<LayerZeroOftVulnerability> {
        // lzCompose() allows callbacks - must be reentrancy safe
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for compose callback
            let mut has_compose_callback = false;
            let mut has_reentrancy_guard = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Compose callback (DELEGATECALL or CALL)
                if self.bytecode[j] == 0xF4 || self.bytecode[j] == 0xF1 {
                    has_compose_callback = true;
                }
                
                // Reentrancy guard
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        has_reentrancy_guard = true;
                    }
                }
            }
            
            if has_compose_callback && !has_reentrancy_guard {
                return Some(LayerZeroOftVulnerability {
                    vulnerability_type: LayerZeroOftVulnerabilityType::ComposeCallReentrancy,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "lzCompose callback lacks reentrancy protection. Attacker can reenter \
                                during compose call to manipulate token balances.".to_string(),
                    exploit_scenario: "1. User sends OFT cross-chain with compose message\n\
                                      2. Destination chain calls lzCompose() on receiver\n\
                                      3. Receiver is attacker's malicious contract\n\
                                      4. Attacker reenters OFT contract during compose\n\
                                      5. Token balance not yet updated\n\
                                      6. Attacker transfers tokens to self\n\
                                      7. Original compose completes, credits tokens again\n\
                                      8. Attacker gets 2x tokens from single transfer\n\
                                      9. $10M+ possible with repeated attacks".to_string(),
                    recommendation: "Add nonReentrant modifier to lzCompose(). Update state before \
                                  external calls. Use checks-effects-interactions pattern. Validate \
                                  compose caller. Add compose message validation. Reference: OpenZeppelin \
                                  ReentrancyGuard.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_adapter_params_exploit(&self) -> Option<LayerZeroOftVulnerability> {
        // AdapterParams control gas - must be validated
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for adapter params usage
            let mut uses_adapter_params = false;
            let mut validates_params = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Adapter params processing (CALLDATALOAD)
                if self.bytecode[j] == 0x35 {
                    uses_adapter_params = true;
                }
                
                // Params validation (size or content check)
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                    validates_params = true;
                }
            }
            
            if uses_adapter_params && !validates_params {
                return Some(LayerZeroOftVulnerability {
                    vulnerability_type: LayerZeroOftVulnerabilityType::AdapterParamsExploit,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "AdapterParams used without validation. Attacker can manipulate gas \
                                parameters to grief or drain relayer funds.".to_string(),
                    exploit_scenario: "1. OFT allows custom adapterParams for gas specification\n\
                                      2. No validation of gas amount\n\
                                      3. Attacker sets gasLimit = 100M in adapterParams\n\
                                      4. Relayer must use specified gas\n\
                                      5. Relayer pays massive gas cost on destination\n\
                                      6. Attacker repeats with thousands of txs\n\
                                      7. Relayer drained of funds via gas griefing\n\
                                      8. Cross-chain messages stop processing\n\
                                      9. $1M+ relayer funds stolen".to_string(),
                    recommendation: "Validate adapterParams: require(gasLimit <= MAX_GAS_LIMIT). \
                                  Check params version. Validate airdrop amounts. Add minimum fee \
                                  requirement. Implement relayer protection. Reference: LayerZero \
                                  adapter params specification.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_oft_minting_exploit(&self) -> Option<LayerZeroOftVulnerability> {
        // OFT minting must be restricted to LayerZero endpoint
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for token minting
            let mut mints_tokens = false;
            let mut validates_minter = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Minting (balance increase via SSTORE)
                if self.bytecode[j] == 0x01 && // ADD
                   j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x55 { // SSTORE
                    mints_tokens = true;
                }
                
                // Minter validation
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        validates_minter = true;
                    }
                }
            }
            
            if mints_tokens && !validates_minter {
                return Some(LayerZeroOftVulnerability {
                    vulnerability_type: LayerZeroOftVulnerabilityType::OFTMintingExploit,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "OFT minting not restricted to LayerZero endpoint. Anyone can mint \
                                unlimited tokens on destination chain.".to_string(),
                    exploit_scenario: "1. OFT contract should only mint when receiving LayerZero message\n\
                                      2. Mint function missing onlyEndpoint modifier\n\
                                      3. Attacker directly calls _mint() or similar\n\
                                      4. Mints 1B tokens to self on Arbitrum\n\
                                      5. No tokens locked on source chain\n\
                                      6. Supply inflated massively\n\
                                      7. Token price crashes to near zero\n\
                                      8. Legitimate holders lose everything\n\
                                      9. $100M+ market cap destroyed".to_string(),
                    recommendation: "Restrict minting: require(msg.sender == address(lzEndpoint)). \
                                  Use onlyEndpoint modifier. Validate srcChainId and srcAddress. \
                                  Verify message nonce. Add minting caps. Reference: LayerZero OFT \
                                  base contract.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_payload_validation_missing(&self) -> Option<LayerZeroOftVulnerability> {
        // Cross-chain payload must be validated
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for payload processing
            let mut processes_payload = false;
            let mut validates_payload = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Payload processing (CALLDATALOAD or memory operations)
                if self.bytecode[j] == 0x35 || self.bytecode[j] == 0x51 { // CALLDATALOAD/MLOAD
                    processes_payload = true;
                }
                
                // Payload validation (size or hash check)
                if self.bytecode[j] == 0x20 { // KECCAK256
                    validates_payload = true;
                }
            }
            
            if processes_payload && !validates_payload {
                return Some(LayerZeroOftVulnerability {
                    vulnerability_type: LayerZeroOftVulnerabilityType::PayloadSizeMismatch,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Cross-chain payload processed without validation. Malformed payload \
                                can cause incorrect token amounts or recipient addresses.".to_string(),
                    exploit_scenario: "1. OFT expects payload: (recipient, amount)\n\
                                      2. No validation of payload size or structure\n\
                                      3. Attacker sends malformed payload: (recipient, amount, extra_data)\n\
                                      4. Extra data interpreted as another recipient\n\
                                      5. Or amount field overflows into recipient\n\
                                      6. Tokens sent to wrong address\n\
                                      7. Or massive amount minted due to overflow\n\
                                      8. $20M+ lost to payload manipulation".to_string(),
                    recommendation: "Validate payload: require(payload.length == EXPECTED_SIZE). \
                                  Use structured decoding with error handling. Verify amount bounds. \
                                  Validate recipient address. Add payload hash check. Reference: \
                                  LayerZero payload encoding standards.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trusted_relayer_bypass() {
        // Message reception without source validation
        let bytecode = vec![
            0xF1, // CALL (message received, no CALLER check)
        ];
        
        let detector = LayerZeroOftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            LayerZeroOftVulnerabilityType::TrustedRelayerBypass
        )));
    }
    
    #[test]
    fn test_compose_call_reentrancy() {
        // Compose callback without reentrancy guard
        let bytecode = vec![
            0xF4, // DELEGATECALL (compose, no guard)
        ];
        
        let detector = LayerZeroOftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            LayerZeroOftVulnerabilityType::ComposeCallReentrancy
        )));
    }
    
    #[test]
    fn test_oft_minting_exploit() {
        // Minting without endpoint validation
        let bytecode = vec![
            0x01, // ADD
            0x55, // SSTORE (mint without CALLER check)
        ];
        
        let detector = LayerZeroOftDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            LayerZeroOftVulnerabilityType::OFTMintingExploit
        )));
    }
}
