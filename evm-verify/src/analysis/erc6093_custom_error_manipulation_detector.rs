pub struct Erc6093CustomErrorManipulationDetector {
    bytecode: Vec<u8>,
}

impl Erc6093CustomErrorManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_missing_custom_errors() {
            findings.push("ERC6093: Missing required custom error definitions".to_string());
        }

        if self.has_incorrect_error_params() {
            findings.push("ERC6093: Custom error parameters don't match standard".to_string());
        }

        if self.has_error_suppression() {
            findings.push("ERC6093: Error conditions suppressed instead of using custom errors".to_string());
        }

        findings
    }

    fn has_missing_custom_errors(&self) -> bool {
        // Check for ERC20/721/1155 functions without ERC6093 errors
        let token_functions = [b"transfer", b"approve", b"mint", b"burn"];
        let has_token_funcs = token_functions.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_token_funcs {
            // Look for custom error definitions
            let erc6093_errors = [
                b"ERC20InsufficientBalance",
                b"ERC20InvalidSender",
                b"ERC721InvalidOwner",
                b"ERC1155InsufficientBalance",
            ];
            
            let has_custom_errors = erc6093_errors.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_custom_errors;
        }
        
        false
    }

    fn has_incorrect_error_params(&self) -> bool {
        // Check if custom errors exist but have wrong signatures
        let error_patterns = [b"ERC20", b"ERC721", b"ERC1155"];
        let has_errors = error_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_errors {
            // Look for error selector encoding (first 4 bytes of keccak256)
            // This is simplified - full implementation would verify exact selectors
            let has_revert = self.bytecode.iter().any(|&b| b == 0xfd); // REVERT
            return has_revert;
        }
        
        false
    }

    fn has_error_suppression(&self) -> bool {
        // Check for reverts with generic messages instead of custom errors
        let has_revert = self.bytecode.iter().any(|&b| b == 0xfd); // REVERT
        
        if has_revert {
            // Look for string error messages (old style)
            let string_patterns = [b"Error", b"Failed", b"Invalid"];
            let has_string_errors = string_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            // Check for custom errors
            let custom_error_patterns = [b"ERC20", b"ERC721", b"ERC1155"];
            let has_custom_errors = custom_error_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return has_string_errors && !has_custom_errors;
        }
        
        false
    }
}
