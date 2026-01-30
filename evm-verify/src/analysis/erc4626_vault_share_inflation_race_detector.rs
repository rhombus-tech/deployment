pub struct Erc4626VaultShareInflationRaceDetector {
    bytecode: Vec<u8>,
}

impl Erc4626VaultShareInflationRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_first_depositor_attack() {
            findings.push("ERC4626: First depositor share inflation attack possible".to_string());
        }

        if self.has_donation_attack() {
            findings.push("ERC4626: Vault vulnerable to donation-based share manipulation".to_string());
        }

        if self.has_rounding_exploit() {
            findings.push("ERC4626: Share calculation rounding can be exploited".to_string());
        }

        findings
    }

    fn has_first_depositor_attack(&self) -> bool {
        let vault_patterns = [b"deposit", b"mint", b"totalAssets", b"totalSupply"];
        let has_vault = vault_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_vault {
            // Check for minimum deposit protection
            let min_patterns = [b"minDeposit", b"MIN_DEPOSIT", b"minimumShares"];
            let has_min_protection = min_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_min_protection;
        }
        
        false
    }

    fn has_donation_attack(&self) -> bool {
        let asset_patterns = [b"totalAssets", b"balanceOf", b"asset"];
        let has_assets = asset_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_assets {
            // Check if direct transfers are accounted for
            let accounting_patterns = [b"accountedAssets", b"trackedBalance", b"depositedAssets"];
            let has_accounting = accounting_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_accounting;
        }
        
        false
    }

    fn has_rounding_exploit(&self) -> bool {
        let conversion_patterns = [b"convertToShares", b"convertToAssets", b"previewDeposit"];
        let has_conversion = conversion_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_conversion {
            // Look for DIV opcode (potential rounding issues)
            let has_division = self.bytecode.iter().any(|&b| b == 0x04); // DIV
            
            if has_division {
                // Check for rounding protection
                let rounding_patterns = [b"roundUp", b"roundDown", b"ROUNDING"];
                let has_rounding_control = rounding_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return !has_rounding_control;
            }
        }
        
        false
    }
}
