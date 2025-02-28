#[cfg(test)]
mod tests {
    use ethers::types::Bytes;
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use crate::bytecode::security::SecurityWarningKind;

    #[test]
    fn test_unchecked_calls_detection() {
        // Create a simple bytecode with an unchecked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x00); // Some other opcode, not ISZERO
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::UncheckedCallReturn);
        
        // Create a bytecode with a checked CALL
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0xF1); // CALL
        bytecode.push(0x15); // ISZERO - checking the return value
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_unchecked_calls().unwrap();
        
        assert_eq!(warnings.len(), 0);
    }
    
    #[test]
    fn test_txorigin_usage_detection() {
        // Create a simple bytecode with tx.origin usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x32); // ORIGIN
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_txorigin_usage().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::TxOriginUsage);
        
        // Create a bytecode with tx.origin used for authorization
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x32); // ORIGIN
        bytecode.push(0x14); // EQ - comparison
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_txorigin_usage().unwrap();
        
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].kind, SecurityWarningKind::TxOriginAuth);
    }
    
    #[test]
    fn test_gas_limit_issues_detection() {
        // Create a simple bytecode with GASLIMIT usage
        let mut bytecode = vec![0x00]; // STOP
        bytecode.push(0x45); // GASLIMIT
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let warnings = analyzer.detect_gas_limit_issues().unwrap();
        
        assert!(warnings.len() > 0);
        assert!(warnings[0].description.contains("Block gas limit dependence"));
    }
    
    #[test]
    fn test_security_checks_in_test_mode() {
        // Create a bytecode with multiple security issues
        let mut bytecode = vec![];
        bytecode.push(0x32); // ORIGIN
        bytecode.push(0x45); // GASLIMIT
        bytecode.push(0xF1); // CALL
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);
        
        // All of these should return empty vectors in test mode
        assert_eq!(analyzer.detect_unchecked_calls().unwrap().len(), 0);
        assert_eq!(analyzer.detect_txorigin_usage().unwrap().len(), 0);
        assert_eq!(analyzer.detect_gas_limit_issues().unwrap().len(), 0);
    }
    
    #[test]
    fn test_integration_with_analyze() {
        // Create a bytecode with multiple security issues
        let mut bytecode = vec![];
        bytecode.push(0x32); // ORIGIN
        bytecode.push(0x45); // GASLIMIT
        bytecode.push(0xF1); // CALL
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        let results = analyzer.analyze().unwrap();
        
        // Check that warnings were generated
        assert!(results.warnings.len() > 0);
    }
}
