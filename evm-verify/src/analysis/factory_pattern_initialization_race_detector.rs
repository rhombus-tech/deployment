pub struct FactoryPatternInitializationRaceDetector {
    bytecode: Vec<u8>,
}

impl FactoryPatternInitializationRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_factory_initialization_race() {
            findings.push("Factory pattern: Initialization race condition detected".to_string());
        }

        if self.has_deployment_frontrun_risk() {
            findings.push("Factory pattern: Deployment frontrun vulnerability detected".to_string());
        }

        if self.has_unprotected_factory_create() {
            findings.push("Factory pattern: Unprotected factory create function".to_string());
        }

        findings
    }

    fn has_factory_initialization_race(&self) -> bool {
        let factory_patterns: &[&[u8]] = &[
            b"createClone",
            b"deployContract",
            b"initialize",
            b"factory",
        ];
        
        for pattern in factory_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_deployment_frontrun_risk(&self) -> bool {
        let frontrun_patterns: &[&[u8]] = &[
            b"create2",
            b"CREATE2",
            b"salt",
            b"deploy",
        ];
        
        for pattern in frontrun_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_unprotected_factory_create(&self) -> bool {
        let create_patterns: &[&[u8]] = &[
            b"newContract",
            b"createNew",
            b"deployNew",
            b"instantiate",
        ];
        
        for pattern in create_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
