// Tests for new vulnerability analyzers (zero false positives)

use crate::analysis::*;
use crate::bytecode::opcodes::Opcode;

#[cfg(test)]
mod account_abstraction_tests {
    use super::*;
    
    #[test]
    fn test_paymaster_gas_manipulation_detected() {
        let analyzer = account_abstraction_exploits::AccountAbstractionAnalyzer::new();
        
        // Vulnerable bytecode: paymaster using GAS opcode
        let bytecode = create_vulnerable_paymaster();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                account_abstraction_exploits::AAVulnerabilityType::PaymasterGasManipulation
            )),
            "Should detect paymaster gas manipulation"
        );
    }
    
    #[test]
    fn test_safe_paymaster_no_false_positive() {
        let analyzer = account_abstraction_exploits::AccountAbstractionAnalyzer::new();
        
        // Safe paymaster without GAS opcode
        let bytecode = create_safe_paymaster();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe paymaster should have zero vulnerabilities");
    }
    
    fn create_vulnerable_paymaster() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0x5a,       // GAS (vulnerable!)
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_paymaster() -> Vec<u8> {
        vec![
            0x60, 0x01, // PUSH1 0x01
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod intent_protocol_tests {
    use super::*;
    
    #[test]
    fn test_intent_front_running_detected() {
        let analyzer = intent_protocol_exploits::IntentProtocolAnalyzer::new();
        
        // Vulnerable: no commit-reveal
        let bytecode = create_vulnerable_intent();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                intent_protocol_exploits::IntentVulnerabilityType::IntentFrontRunning
            )),
            "Should detect intent front-running risk"
        );
    }
    
    #[test]
    fn test_safe_intent_no_false_positive() {
        let analyzer = intent_protocol_exploits::IntentProtocolAnalyzer::new();
        
        // Safe: has commit-reveal
        let bytecode = create_safe_intent();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe intent protocol should have zero vulnerabilities");
    }
    
    fn create_vulnerable_intent() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_intent() -> Vec<u8> {
        vec![
            0x54,       // SLOAD (loading commitment)
            0x60, 0x01, // PUSH1 0x01
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod layer2_tests {
    use super::*;
    
    #[test]
    fn test_sequencer_censorship_detected() {
        let analyzer = layer2_exploits::Layer2Analyzer::new();
        
        // Vulnerable: no force-inclusion
        let bytecode = create_vulnerable_l2();
        
        let vulns = analyzer.analyze(&bytecode, layer2_exploits::Layer2Type::OptimisticRollup);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                layer2_exploits::L2VulnerabilityType::SequencerCensorship
            )),
            "Should detect sequencer censorship risk"
        );
    }
    
    #[test]
    fn test_safe_l2_no_false_positive() {
        let analyzer = layer2_exploits::Layer2Analyzer::new();
        
        // Safe: has force-inclusion
        let bytecode = create_safe_l2();
        
        let vulns = analyzer.analyze(&bytecode, layer2_exploits::Layer2Type::OptimisticRollup);
        
        // May have other L2 vulnerabilities, but not censorship
        assert!(
            !vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                layer2_exploits::L2VulnerabilityType::SequencerCensorship
            )),
            "Safe L2 should not have censorship vulnerability"
        );
    }
    
    fn create_vulnerable_l2() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_l2() -> Vec<u8> {
        vec![
            0x63, 0x12, 0x34, 0x56, 0x78, // PUSH4 (force-inclusion selector)
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod hooks_callback_tests {
    use super::*;
    
    #[test]
    fn test_hook_reentrancy_detected() {
        let analyzer = hooks_callback_exploits::HooksCallbackAnalyzer::new();
        
        // Vulnerable: hook with external call, no guard
        let bytecode = create_vulnerable_hook();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                hooks_callback_exploits::HooksVulnerabilityType::HookReentrancy
            )),
            "Should detect hook reentrancy"
        );
    }
    
    #[test]
    fn test_safe_hook_no_false_positive() {
        let analyzer = hooks_callback_exploits::HooksCallbackAnalyzer::new();
        
        // Safe: no external calls
        let bytecode = create_safe_hook();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe hook should have zero vulnerabilities");
    }
    
    fn create_vulnerable_hook() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0xf1,       // CALL (vulnerable!)
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_hook() -> Vec<u8> {
        vec![
            0x60, 0x01, // PUSH1 0x01
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod concentrated_liquidity_tests {
    use super::*;
    
    #[test]
    fn test_tick_manipulation_detected() {
        let analyzer = concentrated_liquidity_exploits::ConcentratedLiquidityAnalyzer::new();
        
        // Vulnerable: no tick spacing validation
        let bytecode = create_vulnerable_cl();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                concentrated_liquidity_exploits::CLVulnerabilityType::TickManipulation
            )),
            "Should detect tick manipulation"
        );
    }
    
    #[test]
    fn test_safe_cl_no_false_positive() {
        let analyzer = concentrated_liquidity_exploits::ConcentratedLiquidityAnalyzer::new();
        
        // Safe: has tick spacing validation (MOD)
        let bytecode = create_safe_cl();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe CL should have zero vulnerabilities");
    }
    
    fn create_vulnerable_cl() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_cl() -> Vec<u8> {
        vec![
            0x60, 0x01, // PUSH1 0x01
            0x06,       // MOD (tick spacing validation)
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod privacy_zk_tests {
    use super::*;
    
    #[test]
    fn test_nullifier_double_spend_detected() {
        let analyzer = privacy_zk_exploits::PrivacyZKAnalyzer::new();
        
        // Vulnerable: nullifier not stored
        let bytecode = create_vulnerable_privacy();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                privacy_zk_exploits::PrivacyVulnerabilityType::NullifierDoubleSpend
            )),
            "Should detect nullifier double-spend"
        );
    }
    
    #[test]
    fn test_safe_privacy_no_false_positive() {
        let analyzer = privacy_zk_exploits::PrivacyZKAnalyzer::new();
        
        // Safe: stores nullifier
        let bytecode = create_safe_privacy();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe privacy protocol should have zero vulnerabilities");
    }
    
    fn create_vulnerable_privacy() -> Vec<u8> {
        vec![
            0x54,       // SLOAD
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN (no SSTORE!)
        ]
    }
    
    fn create_safe_privacy() -> Vec<u8> {
        vec![
            0x54,       // SLOAD
            0x55,       // SSTORE (stores nullifier)
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod mev_protection_tests {
    use super::*;
    
    #[test]
    fn test_no_slippage_protection_detected() {
        let analyzer = mev_protection_exploits::MEVProtectionAnalyzer::new();
        
        // Vulnerable: no slippage check
        let bytecode = create_vulnerable_mev();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                mev_protection_exploits::MEVVulnerabilityType::NoSlippageProtection
            )),
            "Should detect missing slippage protection"
        );
    }
    
    #[test]
    fn test_safe_mev_no_false_positive() {
        let analyzer = mev_protection_exploits::MEVProtectionAnalyzer::new();
        
        // Safe: has slippage check
        let bytecode = create_safe_mev();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Safe MEV protection should have zero vulnerabilities");
    }
    
    fn create_vulnerable_mev() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0x00
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_mev() -> Vec<u8> {
        vec![
            0x60, 0x01, // PUSH1 0x01
            0x11,       // GT (slippage check)
            0xf3,       // RETURN
        ]
    }
}

#[cfg(test)]
mod censorship_tests {
    use super::*;
    
    #[test]
    fn test_whitelist_only_detected() {
        let analyzer = censorship_resistance_exploits::CensorshipAnalyzer::new();
        
        // Vulnerable: whitelist with revert
        let bytecode = create_vulnerable_censorship();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert!(
            vulns.iter().any(|v| matches!(
                v.vulnerability_type,
                censorship_resistance_exploits::CensorshipVulnerabilityType::WhitelistOnly
            )),
            "Should detect whitelist-only access"
        );
    }
    
    #[test]
    fn test_open_access_no_false_positive() {
        let analyzer = censorship_resistance_exploits::CensorshipAnalyzer::new();
        
        // Safe: no whitelist checks
        let bytecode = create_safe_censorship();
        
        let vulns = analyzer.analyze(&bytecode);
        
        assert_eq!(vulns.len(), 0, "Open access should have zero vulnerabilities");
    }
    
    fn create_vulnerable_censorship() -> Vec<u8> {
        vec![
            0x54,       // SLOAD (loading whitelist)
            0xfd,       // REVERT (blocks non-whitelisted)
            0xf3,       // RETURN
        ]
    }
    
    fn create_safe_censorship() -> Vec<u8> {
        vec![
            0x60, 0x01, // PUSH1 0x01
            0xf3,       // RETURN (no whitelist)
        ]
    }
}

#[test]
fn test_all_analyzers_zero_false_positives_on_empty() {
    // Empty bytecode should have zero vulnerabilities
    let empty_bytecode = vec![];
    
    let aa = account_abstraction_exploits::AccountAbstractionAnalyzer::new();
    let intent = intent_protocol_exploits::IntentProtocolAnalyzer::new();
    let l2 = layer2_exploits::Layer2Analyzer::new();
    let hooks = hooks_callback_exploits::HooksCallbackAnalyzer::new();
    let cl = concentrated_liquidity_exploits::ConcentratedLiquidityAnalyzer::new();
    let privacy = privacy_zk_exploits::PrivacyZKAnalyzer::new();
    let mev = mev_protection_exploits::MEVProtectionAnalyzer::new();
    let censorship = censorship_resistance_exploits::CensorshipAnalyzer::new();
    
    assert_eq!(aa.analyze(&empty_bytecode).len(), 0);
    assert_eq!(intent.analyze(&empty_bytecode).len(), 0);
    assert_eq!(l2.analyze(&empty_bytecode, layer2_exploits::Layer2Type::ZKRollup).len(), 0);
    assert_eq!(hooks.analyze(&empty_bytecode).len(), 0);
    assert_eq!(cl.analyze(&empty_bytecode).len(), 0);
    assert_eq!(privacy.analyze(&empty_bytecode).len(), 0);
    assert_eq!(mev.analyze(&empty_bytecode).len(), 0);
    assert_eq!(censorship.analyze(&empty_bytecode).len(), 0);
    
    println!("✅ All 8 analyzers have ZERO false positives on empty bytecode");
}
