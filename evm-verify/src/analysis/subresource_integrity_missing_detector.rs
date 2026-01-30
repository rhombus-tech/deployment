pub struct SubresourceIntegrityMissingDetector {
    bytecode: Vec<u8>,
}

impl SubresourceIntegrityMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_external_resource_without_sri() {
            findings.push("SRI missing: External resource loaded without subresource integrity".to_string());
        }

        if self.has_unverified_script_tags() {
            findings.push("SRI missing: Script tags without integrity attribute".to_string());
        }

        if self.has_unverified_stylesheet() {
            findings.push("SRI missing: Stylesheet loaded without integrity verification".to_string());
        }

        if self.has_insecure_resource_loading() {
            findings.push("SRI missing: Insecure resource loading detected".to_string());
        }

        findings
    }

    fn has_external_scripts_without_sri(&self) -> bool {
        // Check for <script src="https://..." without integrity attribute
        let has_external_script = self.bytecode.windows(11).any(|w| w == b"<script src");
        
        if has_external_script {
            // Check for https:// URL
            let has_https = self.bytecode.windows(8).any(|w| w == b"https://");
            // Check for integrity attribute
            let has_integrity = self.bytecode.windows(9).any(|w| w == b"integrity");
            
            return has_https && !has_integrity;
        }
        
        false
    }

    fn has_stylesheet_without_integrity(&self) -> bool {
        // Check for <link rel="stylesheet" href="https://..." without integrity
        let has_stylesheet = self.bytecode.windows(15).any(|w| w == b"rel=\"stylesheet\"");
        
        if has_stylesheet {
            let has_https = self.bytecode.windows(8).any(|w| w == b"https://");
            let has_integrity = self.bytecode.windows(9).any(|w| w == b"integrity");
            
            return has_https && !has_integrity;
        }
        
        false
    }

    fn has_insecure_resource_loading(&self) -> bool {
        // Check for resources loaded over HTTP instead of HTTPS
        let has_http = self.bytecode.windows(7).any(|w| w == b"http://");
        
        // Check for resources without crossorigin attribute (required for SRI)
        if has_http {
            return true;
        }
        
        // Check for external resources without crossorigin
        let has_external_resource = self.bytecode.windows(4).any(|w| w == b"src=" || w == b"href");
        if has_external_resource {
            let has_crossorigin = self.bytecode.windows(11).any(|w| w == b"crossorigin");
            let has_external_domain = self.bytecode.windows(8).any(|w| w == b"https://");
            
            return has_external_domain && !has_crossorigin;
        }
        
        false
    }
    
    fn has_external_resource_without_sri(&self) -> bool {
        self.has_external_scripts_without_sri()
    }
    
    fn has_unverified_script_tags(&self) -> bool {
        self.has_external_scripts_without_sri()
    }
    
    fn has_unverified_stylesheet(&self) -> bool {
        self.has_stylesheet_without_integrity()
    }
}
