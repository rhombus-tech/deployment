// Configuration for EVM Verify
//
// This module handles configuration for the EVM Verify tool.

use crate::api::types::AnalysisConfig;
use anyhow::Result;
use std::path::Path;
use std::fs;
use serde_json;

/// Configuration manager for EVM Verify
pub struct ConfigManager;

impl ConfigManager {
    /// Load configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<AnalysisConfig> {
        let config_str = fs::read_to_string(path)?;
        let config = serde_json::from_str(&config_str)?;
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(config: &AnalysisConfig, path: P) -> Result<()> {
        let config_str = serde_json::to_string_pretty(config)?;
        fs::write(path, config_str)?;
        Ok(())
    }
    
    /// Create a builder for configuration
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder for creating configurations
pub struct ConfigBuilder {
    config: AnalysisConfig,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }
}

impl ConfigBuilder {
    /// Set whether to analyze constructor code
    pub fn analyze_constructor(mut self, value: bool) -> Self {
        self.config.analyze_constructor = value;
        self
    }
    
    /// Set whether to analyze runtime code
    pub fn analyze_runtime(mut self, value: bool) -> Self {
        self.config.analyze_runtime = value;
        self
    }
    
    /// Set the maximum depth for analysis
    pub fn max_depth(mut self, value: usize) -> Self {
        self.config.max_depth = value;
        self
    }
    
    /// Set whether to detect reentrancy vulnerabilities
    pub fn detect_reentrancy(mut self, value: bool) -> Self {
        self.config.detect_reentrancy = value;
        self
    }
    
    /// Set whether to detect cross-contract reentrancy vulnerabilities
    pub fn detect_cross_contract_reentrancy(mut self, value: bool) -> Self {
        self.config.detect_cross_contract_reentrancy = value;
        self
    }
    
    /// Set whether to detect arithmetic vulnerabilities
    pub fn detect_arithmetic(mut self, value: bool) -> Self {
        self.config.detect_arithmetic = value;
        self
    }
    
    /// Set whether to detect access control vulnerabilities
    pub fn detect_access_control(mut self, value: bool) -> Self {
        self.config.detect_access_control = value;
        self
    }
    
    /// Set whether to detect delegate call vulnerabilities
    pub fn detect_delegate_call(mut self, value: bool) -> Self {
        self.config.detect_delegate_call = value;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> AnalysisConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_config_builder() {
        let config = ConfigManager::builder()
            .analyze_constructor(false)
            .max_depth(50)
            .detect_reentrancy(true)
            .build();
            
        assert!(!config.analyze_constructor);
        assert!(config.analyze_runtime);
        assert_eq!(config.max_depth, 50);
        assert!(config.detect_reentrancy);
    }
    
    #[test]
    fn test_config_save_load() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("config.json");
        
        let config = ConfigManager::builder()
            .analyze_constructor(false)
            .max_depth(50)
            .build();
            
        ConfigManager::save_to_file(&config, &file_path)?;
        let loaded_config = ConfigManager::load_from_file(&file_path)?;
        
        assert_eq!(loaded_config.analyze_constructor, config.analyze_constructor);
        assert_eq!(loaded_config.max_depth, config.max_depth);
        
        Ok(())
    }
}
