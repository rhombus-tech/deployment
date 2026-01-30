/// Cross-Contract Arbitrary Call Chain Detector
///
/// Detects vulnerabilities where arbitrary calls can be chained across
/// multiple protocols, enabling complex multi-step exploits.
///
/// Examples:
/// - LI.FI Protocol: Arbitrary call routing allowed draining multiple protocols
/// - Bridge aggregators with unvalidated target contracts
/// - DEX aggregators allowing arbitrary swap paths
/// - Multi-call contracts without target validation
///
/// Real exploits: LI.FI ($10M), Transit Swap ($21M), Poly Network ($611M)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractArbitraryCallChainVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub chain_type: CallChainType,
    pub attack_vector: AttackVector,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallChainType {
    /// User-controlled call targets
    UserControlledTargets,
    /// User-controlled call data
    UserControlledCalldata,
    /// Unrestricted multicall/batch operations
    UnrestrictedMulticall,
    /// Arbitrary delegatecall chain
    DelegatecallChain,
    /// Cross-protocol call routing
    CallRouting,
    /// Approval + arbitrary call combination
    ApprovalExploitation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttackVector {
    /// Direct arbitrary call
    DirectArbitraryCall,
    /// Batch/multicall with no target whitelist
    UnvalidatedBatch,
    /// Callback hook exploitation
    CallbackExploitation,
    /// Nested call chains
    NestedCalls,
    /// Approval manipulation via arbitrary calls
    ApprovalSteal,
}

pub struct CrossContractArbitraryCallChainAnalyzer;

impl CrossContractArbitraryCallChainAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractArbitraryCallChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for user-controlled call targets
        if self.has_user_controlled_targets(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::Critical,
                description: "User can specify arbitrary call targets without whitelist validation".to_string(),
                location: "Call target loading".to_string(),
                chain_type: CallChainType::UserControlledTargets,
                attack_vector: AttackVector::DirectArbitraryCall,
                impact: "Attacker can call any contract including malicious ones, enabling fund draining".to_string(),
            });
        }

        // Check for user-controlled calldata
        if self.has_user_controlled_calldata(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::Critical,
                description: "User can control calldata passed to external contracts".to_string(),
                location: "Calldata preparation".to_string(),
                chain_type: CallChainType::UserControlledCalldata,
                attack_vector: AttackVector::DirectArbitraryCall,
                impact: "Arbitrary function calls possible, including transferFrom, approve, etc.".to_string(),
            });
        }

        // Check for unrestricted multicall
        if self.has_unrestricted_multicall(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Multicall/batch function allows arbitrary call chains".to_string(),
                location: "Batch processing".to_string(),
                chain_type: CallChainType::UnrestrictedMulticall,
                attack_vector: AttackVector::UnvalidatedBatch,
                impact: "Chained attacks across multiple protocols in single transaction".to_string(),
            });
        }

        // Check for approval exploitation patterns
        if self.has_approval_exploitation(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Arbitrary calls combined with approval management".to_string(),
                location: "Approval + arbitrary call".to_string(),
                chain_type: CallChainType::ApprovalExploitation,
                attack_vector: AttackVector::ApprovalSteal,
                impact: "Attacker can approve own address then drain user tokens via arbitrary call".to_string(),
            });
        }

        // Check for callback exploitation
        if self.has_callback_exploitation(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::High,
                description: "Callback hooks can trigger arbitrary contract calls".to_string(),
                location: "Callback handler".to_string(),
                chain_type: CallChainType::CallRouting,
                attack_vector: AttackVector::CallbackExploitation,
                impact: "Reentrancy or state manipulation via malicious callback targets".to_string(),
            });
        }

        // Check for nested arbitrary calls
        if self.has_nested_arbitrary_calls(bytecode) {
            vulnerabilities.push(CrossContractArbitraryCallChainVulnerability {
                severity: SecuritySeverity::High,
                description: "Multiple levels of arbitrary calls without depth limiting".to_string(),
                location: "Nested call handling".to_string(),
                chain_type: CallChainType::CallRouting,
                attack_vector: AttackVector::NestedCalls,
                impact: "Complex multi-protocol attack chains possible".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_user_controlled_targets(&self, bytecode: &[u8]) -> bool {
        // Look for: CALLDATALOAD for address -> CALL without whitelist check
        // Pattern: Load address from calldata, use in CALL, no SLOAD (whitelist) check
        bytecode.windows(50).any(|window| {
            let has_calldataload = window.contains(&0x35); // CALLDATALOAD
            let has_call = window.contains(&0xf1) || window.contains(&0xfa); // CALL/STATICCALL
            let no_whitelist = !window.contains(&0x54); // No SLOAD (whitelist mapping)
            let no_equality_check = !window.contains(&0x14); // No EQ
            
            has_calldataload && has_call && no_whitelist && no_equality_check
        })
    }

    fn has_user_controlled_calldata(&self, bytecode: &[u8]) -> bool {
        // Look for: CALLDATACOPY -> CALL (user controls entire calldata)
        bytecode.windows(30).any(|window| {
            window.contains(&0x37) && // CALLDATACOPY
            (window.contains(&0xf1) || window.contains(&0xfa)) // CALL/STATICCALL
        }) || bytecode.windows(20).any(|window| {
            // Or: Multiple CALLDATALOAD feeding into CALL
            window.iter().filter(|&&op| op == 0x35).count() >= 2 && // Multiple CALLDATALOAD
            window.contains(&0xf1) // CALL
        })
    }

    fn has_unrestricted_multicall(&self, bytecode: &[u8]) -> bool {
        // Look for multicall signature + loop + arbitrary calls
        let multicall_sigs = [
            &[0xac, 0x9f, 0xd6, 0x58][..], // multicall(bytes[])
            &[0x5a, 0xe4, 0x01, 0xdc][..], // aggregate(Call[])
        ];

        let has_multicall_sig = multicall_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        });

        let has_loop = bytecode.contains(&0x56); // JUMP (loop)
        let has_call = bytecode.contains(&0xf1);
        let no_target_validation = !bytecode.contains(&0x54); // No SLOAD check

        has_multicall_sig && has_loop && has_call && no_target_validation
    }

    fn has_approval_exploitation(&self, bytecode: &[u8]) -> bool {
        // Look for: approve() signature + arbitrary call capability
        let approve_sig = &[0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
        
        bytecode.windows(4).any(|w| w == approve_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0x35) && // CALLDATALOAD (user input)
            window.contains(&0xf1)    // CALL (arbitrary)
        })
    }

    fn has_callback_exploitation(&self, bytecode: &[u8]) -> bool {
        // Look for: callback patterns with user-controlled target
        // Callbacks often use CALL to address loaded from storage or calldata
        bytecode.windows(40).any(|window| {
            // Pattern: SLOAD/CALLDATALOAD -> CALL (callback target)
            (window.contains(&0x54) || window.contains(&0x35)) && // Load target
            window.contains(&0xf1) && // CALL
            !window.contains(&0x3b)    // No EXTCODESIZE validation
        })
    }

    fn has_nested_arbitrary_calls(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple CALL opcodes in close proximity (nested calls)
        let call_positions: Vec<usize> = bytecode.iter()
            .enumerate()
            .filter(|(_, &op)| op == 0xf1 || op == 0xfa)
            .map(|(i, _)| i)
            .collect();

        // Check for 3+ calls within 200 bytes (likely nested/chained)
        call_positions.windows(3).any(|triple| {
            triple[2] - triple[0] < 200
        }) && bytecode.contains(&0x35) // And has user input
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractArbitraryCallChainVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractArbitraryCallChain,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Arbitrary Call Chain: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement strict whitelisting for call targets and validate calldata", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_controlled_targets() {
        let analyzer = CrossContractArbitraryCallChainAnalyzer::new();
        
        // Bytecode: CALLDATALOAD -> CALL (no whitelist check)
        let bytecode = vec![
            0x35, // CALLDATALOAD (target address)
            0xf1, // CALL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(
            v.chain_type,
            CallChainType::UserControlledTargets
        )));
    }

    #[test]
    fn test_multicall() {
        let analyzer = CrossContractArbitraryCallChainAnalyzer::new();
        
        // Bytecode with multicall signature + loop + call
        let bytecode = vec![
            0xac, 0x9f, 0xd6, 0x58, // multicall signature
            0x56,                     // JUMP (loop)
            0xf1,                     // CALL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
