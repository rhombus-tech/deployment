pub struct ContentSecurityPolicyWeaknessDetector {
    bytecode: Vec<u8>,
}

impl ContentSecurityPolicyWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_missing_csp_headers() {
            findings.push("CSP weakness: Missing Content-Security-Policy headers".to_string());
        }

        if self.has_unsafe_csp_directives() {
            findings.push("CSP weakness: Unsafe CSP directives detected (unsafe-inline, unsafe-eval)".to_string());
        }

        if self.has_permissive_csp() {
            findings.push("CSP weakness: Overly permissive CSP configuration".to_string());
        }

        findings
    }

    fn has_missing_csp_headers(&self) -> bool {
        // Check if CSP header is completely absent
        !self.bytecode.windows(24).any(|w| w == b"Content-Security-Policy")
    }

    fn has_weak_csp_directives(&self) -> bool {
        // Check for CSP header with weak directives
        let has_csp = self.bytecode.windows(24).any(|w| w == b"Content-Security-Policy");
        
        if has_csp {
            // Check for wildcard (*) usage in CSP
            let has_wildcard = self.bytecode.windows(15).any(|w| 
                w.contains(&b'*') && (w.windows(4).any(|s| s == b"http") || w.windows(3).any(|s| s == b"src")));
            
            if has_wildcard {
                return true;
            }
            
            // Check for 'unsafe-eval' directive
            let has_unsafe_eval = self.bytecode.windows(11).any(|w| w == b"unsafe-eval");
            if has_unsafe_eval {
                return true;
            }
        }
        
        false
    }

    fn allows_unsafe_inline(&self) -> bool {
        // Check for 'unsafe-inline' in CSP directives
        let has_unsafe_inline = self.bytecode.windows(13).any(|w| w == b"unsafe-inline");
        
        if has_unsafe_inline {
            return true;
        }
        
        // Check for inline event handlers (onClick, onLoad, etc.)
        let inline_handlers = [
            b"onclick=",
            b"onload=",
            b"onerror=",
            b"onmouseover=",
        ];
        
        for handler in &inline_handlers {
            if self.bytecode.windows(handler.len()).any(|w| w == *handler) {
                return true;
            }
        }
        
        false
    }

    fn lacks_frame_ancestors(&self) -> bool {
        // Check if CSP exists but lacks frame-ancestors directive
        let has_csp = self.bytecode.windows(24).any(|w| w == b"Content-Security-Policy");
        
        if has_csp {
            let has_frame_ancestors = self.bytecode.windows(15).any(|w| w == b"frame-ancestors");
            
            // Also check for X-Frame-Options as fallback
            let has_xframe = self.bytecode.windows(15).any(|w| w == b"X-Frame-Options");
            
            return !has_frame_ancestors && !has_xframe;
        }
        
        // No CSP at all is also a problem
        true
    }
    
    fn has_unsafe_csp_directives(&self) -> bool {
        self.allows_unsafe_inline() || self.has_weak_csp_directives()
    }
    
    fn has_permissive_csp(&self) -> bool {
        self.lacks_frame_ancestors()
    }
}
