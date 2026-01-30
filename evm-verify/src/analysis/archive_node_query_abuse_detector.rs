pub struct ArchiveNodeQueryAbuseDetector {
    bytecode: Vec<u8>,
}

impl ArchiveNodeQueryAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unbounded_historical_queries() {
            findings.push("Archive node abuse: Unbounded historical query range".to_string());
        }

        if self.has_excessive_block_range() {
            findings.push("Archive node abuse: Excessive block range in archive queries".to_string());
        }

        if self.lacks_query_pagination() {
            findings.push("Archive node abuse: Missing pagination for large historical queries".to_string());
        }

        findings
    }

    fn has_unbounded_historical_queries(&self) -> bool {
        // Check for historical query patterns without bounds
        let history_patterns = [
            b"getBlock",
            b"getLogs",
            b"getTransactionReceipt",
            b"archive",
        ];
        
        let has_history_query = history_patterns.iter()
            .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_history_query {
            // Look for range limiting patterns
            let range_patterns = [b"fromBlock", b"toBlock", b"range", b"limit"];
            let has_range_limit = range_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_range_limit;
        }
        
        false
    }

    fn has_excessive_block_range(&self) -> bool {
        // Check for large block range queries
        let has_block_query = self.bytecode.windows(8).any(|w| w == b"getBlock" || w == b"getLogs");
        
        if has_block_query {
            // Look for large constants that might indicate excessive range
            // Common safe range: 1000 blocks (0x3E8), 10000 blocks (0x2710)
            for i in 0..self.bytecode.len().saturating_sub(3) {
                if self.bytecode[i] == 0x62 { // PUSH3
                    let value = ((self.bytecode[i+1] as u32) << 16) |
                                ((self.bytecode[i+2] as u32) << 8) |
                                (self.bytecode[i+3] as u32);
                    // Range > 100,000 blocks is excessive
                    if value > 100000 {
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn lacks_query_pagination(&self) -> bool {
        // Check for queries without pagination
        let has_query = self.bytecode.windows(7).any(|w| w == b"getLogs" || w == b"getBlock");
        
        if has_query {
            // Look for pagination indicators
            let pagination_patterns = [
                b"page",
                b"offset",
                b"cursor",
                b"next",
            ];
            
            let has_pagination = pagination_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_pagination;
        }
        
        false
    }
}
