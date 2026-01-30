pub struct CrossMarginIsolatedMarginConfusionDetector {
    bytecode: Vec<u8>,
}

impl CrossMarginIsolatedMarginConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_margin_type_confusion() {
            findings.push("Cross/Isolated margin: Margin type can be confused".to_string());
        }

        if self.has_collateral_leakage() {
            findings.push("Cross/Isolated margin: Collateral can leak between margin modes".to_string());
        }

        if self.has_liquidation_mode_mismatch() {
            findings.push("Cross/Isolated margin: Liquidation logic mismatches margin mode".to_string());
        }

        findings
    }

    fn has_margin_type_confusion(&self) -> bool {
        let cross_patterns: &[&[u8]] = &[b"crossMargin", b"cross", b"CrossMargin"];
        let has_cross = cross_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        let isolated_patterns: &[&[u8]] = &[b"isolatedMargin", b"isolated", b"IsolatedMargin"];
        let has_isolated = isolated_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_cross && has_isolated {
            // Check for mode validation
            let validation_patterns: &[&[u8]] = &[b"validateMode", b"checkMode", b"marginMode"];
            let has_validation = validation_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_validation;
        }
        
        false
    }

    fn has_collateral_leakage(&self) -> bool {
        let collateral_patterns: &[&[u8]] = &[b"collateral", b"Collateral", b"margin"];
        let has_collateral = collateral_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_collateral {
            // Check for mode-specific collateral tracking
            let isolation_patterns: &[&[u8]] = &[b"isolate", b"separate", b"partition"];
            let has_isolation = isolation_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if !has_isolation {
                // Check for transfer operations
                let transfer_patterns: &[&[u8]] = &[b"transfer", b"move", b"allocate"];
                let has_transfer = transfer_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
                
                return has_transfer;
            }
        }
        
        false
    }

    fn has_liquidation_mode_mismatch(&self) -> bool {
        let liquidate_patterns: &[&[u8]] = &[b"liquidate", b"Liquidate"];
        let has_liquidate = liquidate_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_liquidate {
            // Check for margin mode consideration
            let mode_patterns: &[&[u8]] = &[b"mode", b"marginType", b"isIsolated"];
            let has_mode = mode_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_mode;
        }
        
        false
    }
}
