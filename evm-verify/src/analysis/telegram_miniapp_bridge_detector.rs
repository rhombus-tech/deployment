/// Telegram Mini App <> EVM Bridge Vulnerability Detector
///
/// Detects vulnerabilities in Telegram mini-app to EVM bridge implementations.
/// Telegram's 900M users + crypto wallets = massive attack surface.
///
/// Real-world context:
/// - $2B+ in Telegram-based crypto apps (TON, Notcoin, Hamster Kombat)
/// - 500M+ mini-app users, growing 100M/month
/// - Attack surface: TON↔EVM bridging, bot manipulation, mini-app phishing
/// - Risk: One bridge exploit can drain entire Telegram crypto ecosystem

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramMiniAppVulnerability {
    pub vulnerability_type: TelegramMiniAppVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelegramMiniAppVulnerabilityType {
    CrossChainMessageReplay,        // Message replayed between TON/EVM
    TelegramBotManipulation,        // Fake bot initiates transactions
    MiniAppPhishing,                // Malicious mini-app steals wallet access
    InitDataForgery,                // Telegram initData forged
    TonEvmBridgeCensorship,         // Bridge operator censors withdrawals
    WebAppDataValidation,           // WebAppData not validated
    TelegramUserIDSpoofing,         // UserID spoofed to impersonate
    DeeplinkExploitation,           // Malicious deeplink drains wallet
    BotCommandInjection,            // Command injection via bot
    MiniAppIframeAttack,            // Iframe sandboxing bypassed
}

pub struct TelegramMiniAppBridgeDetector {
    bytecode: Vec<u8>,
}

impl TelegramMiniAppBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<TelegramMiniAppVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Cross-chain message replay
        if let Some(vuln) = self.detect_cross_chain_replay() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Telegram initData forgery
        if let Some(vuln) = self.detect_initdata_forgery() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Telegram user ID spoofing
        if let Some(vuln) = self.detect_userid_spoofing() {
            vulnerabilities.push(vuln);
        }
        
        // 4. TON-EVM bridge censorship
        if let Some(vuln) = self.detect_bridge_censorship() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Deeplink exploitation
        if let Some(vuln) = self.detect_deeplink_exploitation() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_cross_chain_replay(&self) -> Option<TelegramMiniAppVulnerability> {
        // Messages from TON must not be replayable on EVM and vice versa
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for cross-chain message handling
            let mut processes_bridge_message = false;
            let mut validates_chain_id = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Bridge message processing (external call)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                    processes_bridge_message = true;
                }
                
                // Chain ID validation
                if self.bytecode[j] == 0x46 { // CHAINID
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        validates_chain_id = true;
                    }
                }
            }
            
            if processes_bridge_message && !validates_chain_id {
                return Some(TelegramMiniAppVulnerability {
                    vulnerability_type: TelegramMiniAppVulnerabilityType::CrossChainMessageReplay,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Bridge processes cross-chain messages without validating source/destination \
                                chain. Same message can be replayed on TON and EVM chains.".to_string(),
                    exploit_scenario: "1. User bridges 1000 TON from TON blockchain to Ethereum\n\
                                      2. Bridge generates proof on TON side\n\
                                      3. User submits proof to Ethereum bridge contract\n\
                                      4. Receives 1000 bridged-TON on Ethereum\n\
                                      5. Attacker captures the proof\n\
                                      6. No chain ID validation in proof\n\
                                      7. Replays same proof on BSC, Polygon, Arbitrum\n\
                                      8. Gets 1000 bridged-TON on each chain\n\
                                      9. 1000 TON turns into 4000 TON (4x attack)\n\
                                      10. $2M+ stolen if exploited at scale\n\
                                      11. Similar to Poly Network $611M exploit".to_string(),
                    recommendation: "Include chain ID in bridge proof: hash(message, sourceChain, destChain). \
                                  Validate chain ID on both sides: require(chainId == EXPECTED_CHAIN). \
                                  Use chain-specific relayer addresses. Implement nonce per chain. \
                                  Add message ID uniqueness check. Reference: LayerZero chain validation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_initdata_forgery(&self) -> Option<TelegramMiniAppVulnerability> {
        // Telegram sends initData - must be validated via bot token
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for Telegram data validation
            let mut processes_telegram_data = false;
            let mut validates_signature = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Data processing (CALLDATALOAD)
                if self.bytecode[j] == 0x35 {
                    processes_telegram_data = true;
                }
                
                // Signature/hash validation
                if self.bytecode[j] == 0x20 || self.bytecode[j] == 0x01 { // KECCAK256/ECRECOVER
                    validates_signature = true;
                }
            }
            
            if processes_telegram_data && !validates_signature {
                return Some(TelegramMiniAppVulnerability {
                    vulnerability_type: TelegramMiniAppVulnerabilityType::InitDataForgery,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Contract processes Telegram initData without validating HMAC signature. \
                                Attacker can forge initData to impersonate any Telegram user.".to_string(),
                    exploit_scenario: "1. Legit mini-app sends initData: {user_id: 12345, auth_date: ...}\n\
                                      2. Contract doesn't validate Telegram's HMAC signature\n\
                                      3. Attacker crafts fake initData: {user_id: 67890, auth_date: ...}\n\
                                      4. user_id 67890 is whale with $1M in wallet\n\
                                      5. Contract accepts fake initData as valid\n\
                                      6. Attacker gains access to whale's wallet\n\
                                      7. Drains $1M\n\
                                      8. $500M+ at risk across all Telegram crypto apps\n\
                                      9. Similar to OAuth signature bypass attacks".to_string(),
                    recommendation: "Validate Telegram initData HMAC: hash_hmac('sha256', data, bot_token). \
                                  Use Telegram's official validation: WebApp.initData. Store bot token \
                                  securely. Verify auth_date is recent. Add nonce to prevent replay. \
                                  Reference: Telegram WebApp authentication docs.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_userid_spoofing(&self) -> Option<TelegramMiniAppVulnerability> {
        // Telegram user ID must be validated from signed initData
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for user ID usage
            let mut uses_user_id = false;
            let mut validates_user_id = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // User ID used for access control
                if self.bytecode[j] == 0x14 { // EQ (checking user ID)
                    uses_user_id = true;
                }
                
                // Signature validation before using ID
                if self.bytecode[j] == 0x20 { // KECCAK256
                    validates_user_id = true;
                }
            }
            
            if uses_user_id && !validates_user_id {
                return Some(TelegramMiniAppVulnerability {
                    vulnerability_type: TelegramMiniAppVulnerabilityType::TelegramUserIDSpoofing,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Contract uses Telegram user ID for access control without validating \
                                ID comes from signed initData. Attacker can spoof any user ID.".to_string(),
                    exploit_scenario: "1. Contract gives admin rights to Telegram user ID 11111\n\
                                      2. Admin can withdraw all funds\n\
                                      3. Contract checks: if (userID == 11111) allowWithdraw()\n\
                                      4. No validation that userID is from Telegram\n\
                                      5. Attacker just sends userID=11111 in request\n\
                                      6. Contract grants admin access\n\
                                      7. Attacker withdraws all funds\n\
                                      8. $100M+ drained from Telegram bot wallet".to_string(),
                    recommendation: "Extract user ID from validated initData only. Never accept user \
                                  ID from user input. Use mapping: telegramUserToAddress[userId]. \
                                  Validate entire initData before extracting userId. Add secondary \
                                  authentication for critical operations. Reference: Telegram Bot API.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_bridge_censorship(&self) -> Option<TelegramMiniAppVulnerability> {
        // Bridge must have escape hatch for censorship resistance
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for bridge operator control
            let mut has_operator_control = false;
            let mut has_escape_hatch = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Operator access control
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        has_operator_control = true;
                    }
                }
                
                // Escape hatch (timelock bypass)
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x10 { // LT
                        has_escape_hatch = true;
                    }
                }
            }
            
            if has_operator_control && !has_escape_hatch {
                return Some(TelegramMiniAppVulnerability {
                    vulnerability_type: TelegramMiniAppVulnerabilityType::TonEvmBridgeCensorship,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Bridge operator has exclusive control over cross-chain messages \
                                with no escape hatch. Users can be censored permanently.".to_string(),
                    exploit_scenario: "1. User locks 10,000 TON on TON chain\n\
                                      2. Waits for bridged TON on Ethereum\n\
                                      3. Bridge operator (centralized) must relay message\n\
                                      4. Operator censors user's transaction\n\
                                      5. No escape hatch or forced inclusion\n\
                                      6. User's 10,000 TON locked forever\n\
                                      7. Can't withdraw from TON or receive on ETH\n\
                                      8. $50M+ can be censored/stolen by malicious operator\n\
                                      9. Similar to centralized exchange freeze".to_string(),
                    recommendation: "Implement escape hatch: after 7 days, allow direct withdrawal. \
                                  Add forced message inclusion. Use decentralized relayer network. \
                                  Implement fraud proofs for operator misbehavior. Add emergency \
                                  withdrawal. Reference: Arbitrum delayed inbox.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_deeplink_exploitation(&self) -> Option<TelegramMiniAppVulnerability> {
        // Telegram deeplinks can trigger wallet actions - must validate
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for automated transaction execution
            let mut auto_executes = false;
            let mut requires_confirmation = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Automatic execution (CALL without prior approval check)
                if self.bytecode[j] == 0xF1 {
                    auto_executes = true;
                }
                
                // User confirmation required
                if self.bytecode[j] == 0x54 { // SLOAD (checking approval state)
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        requires_confirmation = true;
                    }
                }
            }
            
            if auto_executes && !requires_confirmation {
                return Some(TelegramMiniAppVulnerability {
                    vulnerability_type: TelegramMiniAppVulnerabilityType::DeeplinkExploitation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Contract executes transactions from deeplinks without user confirmation. \
                                Malicious deeplink can drain wallet automatically.".to_string(),
                    exploit_scenario: "1. Attacker creates malicious Telegram bot\n\
                                      2. Sends phishing message with deeplink\n\
                                      3. Deeplink: tg://wallet/transfer?to=attacker&amount=1000\n\
                                      4. User clicks deeplink (thinks it's legitimate)\n\
                                      5. Mini-app wallet auto-executes transfer\n\
                                      6. No confirmation dialog shown\n\
                                      7. 1000 USDT sent to attacker\n\
                                      8. User doesn't realize until too late\n\
                                      9. $100M+ stolen via phishing deeplinks\n\
                                      10. Similar to mobile wallet phishing attacks".to_string(),
                    recommendation: "Always require user confirmation for deeplink actions. Show \
                                  transaction preview. Validate deeplink source. Add whitelist for \
                                  trusted domains. Implement transaction limits. Add time delay for \
                                  large transfers. Reference: MetaMask transaction confirmation UX.".to_string(),
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
    fn test_cross_chain_replay() {
        // Bridge message without chain ID validation
        let bytecode = vec![
            0xF1, // CALL (bridge message, no CHAINID check)
        ];
        
        let detector = TelegramMiniAppBridgeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            TelegramMiniAppVulnerabilityType::CrossChainMessageReplay
        )));
    }
    
    #[test]
    fn test_initdata_forgery() {
        // Data processing without signature validation
        let bytecode = vec![
            0x35, // CALLDATALOAD (no KECCAK256 validation)
        ];
        
        let detector = TelegramMiniAppBridgeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            TelegramMiniAppVulnerabilityType::InitDataForgery
        )));
    }
    
    #[test]
    fn test_deeplink_exploitation() {
        // Auto-execution without confirmation
        let bytecode = vec![
            0xF1, // CALL (no SLOAD approval check)
        ];
        
        let detector = TelegramMiniAppBridgeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            TelegramMiniAppVulnerabilityType::DeeplinkExploitation
        )));
    }
}
