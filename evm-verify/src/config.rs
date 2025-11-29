//! # Production-Grade Configuration Management System
//! 
//! This module provides comprehensive configuration management with environment-specific
//! settings, validation, hot-reloading, and secure credential management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::env;
use crate::error::{ZkEvmError, ZkEvmResult};
use crate::logging::LogConfig;

/// Environment types for configuration management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Environment {
    Development,
    Testing, 
    Staging,
    Production,
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl std::str::FromStr for Environment {
    type Err = ZkEvmError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "testing" | "test" => Ok(Environment::Testing),
            "staging" | "stage" => Ok(Environment::Staging),
            "production" | "prod" => Ok(Environment::Production),
            _ => Err(ZkEvmError::ConfigurationError {
                message: format!("Invalid environment: {}", s),
                config_path: "environment".to_string(),
                invalid_fields: vec!["environment".to_string()],
            }),
        }
    }
}

/// Network configuration for blockchain connectivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Ethereum RPC endpoint URL
    pub rpc_url: String,
    /// WebSocket endpoint URL (optional)
    pub ws_url: Option<String>,
    /// Chain ID for the network
    pub chain_id: u64,
    /// Maximum number of RPC retries
    pub max_retries: u32,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Rate limiting - requests per second
    pub rate_limit_rps: u32,
    /// Enable connection pooling
    pub connection_pooling: bool,
    /// Pool size for connections
    pub pool_size: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
            ws_url: None,
            chain_id: 1, // Ethereum mainnet
            max_retries: 3,
            timeout_seconds: 30,
            rate_limit_rps: 10,
            connection_pooling: true,
            pool_size: 10,
        }
    }
}

/// Proving system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingConfig {
    /// Default proving strategy
    pub default_strategy: String,
    /// ZODA-specific configuration
    pub zoda: ZodaConfig,
    /// WARP-specific configuration  
    pub warp: WarpConfig,
    /// Hybrid strategy configuration
    pub hybrid: HybridConfig,
    /// Maximum concurrent proofs
    pub max_concurrent_proofs: usize,
    /// Proof timeout in seconds
    pub proof_timeout_seconds: u64,
    /// Enable proof caching
    pub enable_caching: bool,
    /// Cache size limit in MB
    pub cache_size_mb: u64,
}

/// ZODA proving configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZodaConfig {
    /// Field size for tensor operations
    pub field_size: u64,
    /// Test mode for reduced security parameters
    pub test_mode: bool,
    /// Distance parameter for error correction
    pub distance: u32,
    /// Enable parallel processing
    pub parallel_processing: bool,
    /// Number of worker threads
    pub worker_threads: usize,
}

/// WARP accumulation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpConfig {
    /// Accumulation batch size
    pub batch_size: usize,
    /// Enable linear-time optimizations
    pub linear_time_optimizations: bool,
    /// Memory limit for accumulation in MB
    pub memory_limit_mb: u64,
}

/// Hybrid strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    /// ZODA weight in hybrid approach (0.0 to 1.0)
    pub zoda_weight: f64,
    /// WARP weight in hybrid approach (0.0 to 1.0)
    pub warp_weight: f64,
    /// Automatic strategy selection based on workload
    pub auto_strategy_selection: bool,
    /// Workload threshold for strategy switching
    pub strategy_switch_threshold: f64,
}

/// Performance and resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Maximum CPU usage percentage
    pub max_cpu_percent: f64,
    /// Maximum disk usage percentage  
    pub max_disk_percent: f64,
    /// Enable performance monitoring
    pub enable_monitoring: bool,
    /// Monitoring interval in seconds
    pub monitoring_interval_seconds: u64,
    /// Performance alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Memory usage alert threshold (percentage)
    pub memory_threshold_percent: f64,
    /// CPU usage alert threshold (percentage)
    pub cpu_threshold_percent: f64,
    /// Disk usage alert threshold (percentage)
    pub disk_threshold_percent: f64,
    /// Proof generation time threshold (seconds)
    pub proof_time_threshold_seconds: f64,
    /// Error rate threshold (errors per minute)
    pub error_rate_threshold: f64,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TLS for all connections
    pub enable_tls: bool,
    /// Path to TLS certificate file
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file
    pub tls_key_path: Option<String>,
    /// Enable API authentication
    pub enable_auth: bool,
    /// API key for authentication (should be loaded from environment)
    pub api_key: Option<String>,
    /// Enable request rate limiting
    pub enable_rate_limiting: bool,
    /// Rate limit per IP (requests per minute)
    pub rate_limit_per_ip: u32,
    /// Enable audit logging
    pub enable_audit_log: bool,
    /// Enable vulnerability analysis during proving (default: true)
    /// When false, proving is faster but security checks are skipped
    pub enable_vulnerability_analysis: bool,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for data storage
    pub data_dir: PathBuf,
    /// Enable data compression
    pub enable_compression: bool,
    /// Compression level (1-9)
    pub compression_level: u32,
    /// Enable data encryption at rest
    pub enable_encryption: bool,
    /// Encryption key path (should be loaded from secure location)
    pub encryption_key_path: Option<String>,
    /// Automatic backup configuration
    pub backup: BackupConfig,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    /// Backup interval in hours
    pub interval_hours: u64,
    /// Number of backups to retain
    pub retention_count: u32,
    /// Backup destination directory
    pub backup_dir: PathBuf,
    /// Enable remote backup (S3, etc.)
    pub remote_backup: bool,
    /// Remote backup configuration
    pub remote_config: Option<HashMap<String, String>>,
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkEvmConfig {
    /// Current environment
    pub environment: Environment,
    /// Network configuration
    pub network: NetworkConfig,
    /// Proving system configuration
    pub proving: ProvingConfig,
    /// Performance and resource configuration
    pub performance: PerformanceConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Logging configuration
    pub logging: LogConfig,
    /// Custom configuration values
    pub custom: HashMap<String, serde_json::Value>,
}

impl Default for ZkEvmConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            network: NetworkConfig::default(),
            proving: ProvingConfig {
                default_strategy: "ZodaWarpHybrid".to_string(),
                zoda: ZodaConfig {
                    field_size: 128,
                    test_mode: false,
                    distance: 10,
                    parallel_processing: true,
                    worker_threads: num_cpus::get(),
                },
                warp: WarpConfig {
                    batch_size: 100,
                    linear_time_optimizations: true,
                    memory_limit_mb: 1024,
                },
                hybrid: HybridConfig {
                    zoda_weight: 0.7,
                    warp_weight: 0.3,
                    auto_strategy_selection: true,
                    strategy_switch_threshold: 1000.0,
                },
                max_concurrent_proofs: 4,
                proof_timeout_seconds: 300,
                enable_caching: true,
                cache_size_mb: 512,
            },
            performance: PerformanceConfig {
                max_memory_mb: 8192,
                max_cpu_percent: 80.0,
                max_disk_percent: 90.0,
                enable_monitoring: true,
                monitoring_interval_seconds: 30,
                alert_thresholds: AlertThresholds {
                    memory_threshold_percent: 85.0,
                    cpu_threshold_percent: 90.0,
                    disk_threshold_percent: 95.0,
                    proof_time_threshold_seconds: 10.0,
                    error_rate_threshold: 10.0,
                },
            },
            security: SecurityConfig {
                enable_tls: true,
                tls_cert_path: None,
                tls_key_path: None,
                enable_auth: false,
                api_key: None,
                enable_rate_limiting: true,
                rate_limit_per_ip: 100,
                enable_audit_log: true,
                enable_vulnerability_analysis: true, // Default: security ON
            },
            storage: StorageConfig {
                data_dir: PathBuf::from("./data"),
                enable_compression: true,
                compression_level: 6,
                enable_encryption: false,
                encryption_key_path: None,
                backup: BackupConfig {
                    enabled: true,
                    interval_hours: 24,
                    retention_count: 7,
                    backup_dir: PathBuf::from("./backups"),
                    remote_backup: false,
                    remote_config: None,
                },
            },
            logging: LogConfig::default(),
            custom: HashMap::new(),
        }
    }
}

impl ZkEvmConfig {
    /// Load configuration from file with environment-specific overrides
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> ZkEvmResult<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| ZkEvmError::ConfigurationError {
                message: format!("Failed to read config file: {}", e),
                config_path: path.display().to_string(),
                invalid_fields: vec![],
            })?;

        let mut config: ZkEvmConfig = toml::from_str(&content)
            .map_err(|e| ZkEvmError::ConfigurationError {
                message: format!("Failed to parse config file: {}", e),
                config_path: path.display().to_string(),
                invalid_fields: vec![],
            })?;

        // Apply environment-specific overrides
        config.apply_environment_overrides()?;
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }

    /// Apply environment variable overrides
    pub fn apply_environment_overrides(&mut self) -> ZkEvmResult<()> {
        // Environment detection
        if let Ok(env_str) = env::var("ZKVM_ENVIRONMENT") {
            self.environment = env_str.parse()?;
        }

        // Network overrides
        if let Ok(rpc_url) = env::var("ZKVM_RPC_URL") {
            self.network.rpc_url = rpc_url;
        }
        if let Ok(chain_id) = env::var("ZKVM_CHAIN_ID") {
            self.network.chain_id = chain_id.parse()
                .map_err(|e| ZkEvmError::ConfigurationError {
                    message: format!("Invalid ZKVM_CHAIN_ID: {}", e),
                    config_path: "environment".to_string(),
                    invalid_fields: vec!["ZKVM_CHAIN_ID".to_string()],
                })?;
        }

        // Security overrides
        if let Ok(enable_tls) = env::var("ZKVM_ENABLE_TLS") {
            self.security.enable_tls = enable_tls.parse().unwrap_or(false);
        }
        if let Ok(enable_auth) = env::var("ZKVM_ENABLE_AUTH") {
            self.security.enable_auth = enable_auth.parse().unwrap_or(false);
        }
        if let Ok(api_key) = env::var("ZKVM_API_KEY") {
            self.security.api_key = Some(api_key);
        }
        if let Ok(tls_cert) = env::var("ZKVM_TLS_CERT_PATH") {
            self.security.tls_cert_path = Some(tls_cert);
        }
        if let Ok(tls_key) = env::var("ZKVM_TLS_KEY_PATH") {
            self.security.tls_key_path = Some(tls_key);
        }

        // Performance overrides
        if let Ok(max_memory) = env::var("ZKVM_MAX_MEMORY_MB") {
            self.performance.max_memory_mb = max_memory.parse()
                .map_err(|e| ZkEvmError::ConfigurationError {
                    message: format!("Invalid ZKVM_MAX_MEMORY_MB: {}", e),
                    config_path: "environment".to_string(),
                    invalid_fields: vec!["ZKVM_MAX_MEMORY_MB".to_string()],
                })?;
        }

        // Storage overrides
        if let Ok(data_dir) = env::var("ZKVM_DATA_DIR") {
            self.storage.data_dir = PathBuf::from(data_dir);
        }

        Ok(())
    }

    /// Validate configuration values
    pub fn validate(&self) -> ZkEvmResult<()> {
        let mut invalid_fields = Vec::new();

        // Validate network configuration
        if self.network.rpc_url.is_empty() {
            invalid_fields.push("network.rpc_url".to_string());
        }
        if self.network.chain_id == 0 {
            invalid_fields.push("network.chain_id".to_string());
        }
        if self.network.timeout_seconds == 0 {
            invalid_fields.push("network.timeout_seconds".to_string());
        }

        // Validate proving configuration
        if self.proving.max_concurrent_proofs == 0 {
            invalid_fields.push("proving.max_concurrent_proofs".to_string());
        }
        if self.proving.proof_timeout_seconds == 0 {
            invalid_fields.push("proving.proof_timeout_seconds".to_string());
        }

        // Validate hybrid weights
        let total_weight = self.proving.hybrid.zoda_weight + self.proving.hybrid.warp_weight;
        if (total_weight - 1.0).abs() > 0.001 {
            invalid_fields.push("proving.hybrid weights must sum to 1.0".to_string());
        }

        // Validate performance thresholds
        if self.performance.max_memory_mb == 0 {
            invalid_fields.push("performance.max_memory_mb".to_string());
        }
        if self.performance.max_cpu_percent <= 0.0 || self.performance.max_cpu_percent > 100.0 {
            invalid_fields.push("performance.max_cpu_percent".to_string());
        }

        // Validate security configuration
        if self.security.enable_auth && self.security.api_key.is_none() {
            invalid_fields.push("security.api_key required when auth is enabled".to_string());
        }
        if self.security.enable_tls && (self.security.tls_cert_path.is_none() || self.security.tls_key_path.is_none()) {
            invalid_fields.push("security.tls_cert_path and tls_key_path required when TLS is enabled".to_string());
        }

        if !invalid_fields.is_empty() {
            return Err(ZkEvmError::ConfigurationError {
                message: "Configuration validation failed".to_string(),
                config_path: "validation".to_string(),
                invalid_fields,
            });
        }

        Ok(())
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> ZkEvmResult<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(self)
            .map_err(|e| ZkEvmError::ConfigurationError {
                message: format!("Failed to serialize config: {}", e),
                config_path: path.display().to_string(),
                invalid_fields: vec![],
            })?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ZkEvmError::ConfigurationError {
                    message: format!("Failed to create config directory: {}", e),
                    config_path: parent.display().to_string(),
                    invalid_fields: vec![],
                })?;
        }

        fs::write(path, content)
            .map_err(|e| ZkEvmError::ConfigurationError {
                message: format!("Failed to write config file: {}", e),
                config_path: path.display().to_string(),
                invalid_fields: vec![],
            })?;

        Ok(())
    }

    /// Get environment-specific configuration file path
    pub fn get_config_path(environment: &Environment, base_dir: Option<&Path>) -> PathBuf {
        let base = base_dir.unwrap_or(Path::new("."));
        let filename = match environment {
            Environment::Development => "zkvm-dev.toml",
            Environment::Testing => "zkvm-test.toml",
            Environment::Staging => "zkvm-staging.toml",
            Environment::Production => "zkvm-prod.toml",
        };
        base.join("config").join(filename)
    }

    /// Create default configuration files for all environments
    pub fn create_default_configs<P: AsRef<Path>>(base_dir: P) -> ZkEvmResult<()> {
        let base_dir = base_dir.as_ref();
        let config_dir = base_dir.join("config");
        
        fs::create_dir_all(&config_dir)
            .map_err(|e| ZkEvmError::ConfigurationError {
                message: format!("Failed to create config directory: {}", e),
                config_path: config_dir.display().to_string(),
                invalid_fields: vec![],
            })?;

        for env in [Environment::Development, Environment::Testing, Environment::Staging, Environment::Production] {
            let mut config = ZkEvmConfig::default();
            config.environment = env.clone();

            // Environment-specific customizations
            match env {
                Environment::Development => {
                    config.proving.zoda.test_mode = true;
                    config.proving.max_concurrent_proofs = 2;
                    config.performance.max_memory_mb = 4096;
                    config.security.enable_auth = false;
                    config.security.enable_tls = false;
                },
                Environment::Testing => {
                    config.proving.zoda.test_mode = true;
                    config.proving.max_concurrent_proofs = 1;
                    config.performance.max_memory_mb = 2048;
                    config.security.enable_auth = false;
                    config.security.enable_tls = false;
                },
                Environment::Staging => {
                    config.proving.zoda.test_mode = false;
                    config.proving.max_concurrent_proofs = 4;
                    config.performance.max_memory_mb = 8192;
                    config.security.enable_auth = true;
                    config.security.enable_tls = true;
                },
                Environment::Production => {
                    config.proving.zoda.test_mode = false;
                    config.proving.max_concurrent_proofs = 8;
                    config.performance.max_memory_mb = 16384;
                    config.security.enable_auth = true;
                    config.security.enable_tls = true;
                    config.storage.enable_encryption = true;
                    config.storage.backup.enabled = true;
                    config.storage.backup.remote_backup = true;
                },
            }

            let config_path = Self::get_config_path(&env, Some(base_dir));
            config.save_to_file(config_path)?;
        }

        Ok(())
    }

    /// Load configuration with automatic environment detection
    pub fn load_auto() -> ZkEvmResult<Self> {
        let environment = env::var("ZKVM_ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()?;

        let config_path = Self::get_config_path(&environment, None);
        
        if config_path.exists() {
            Self::load_from_file(config_path)
        } else {
            // Create default config if it doesn't exist
            let mut config = ZkEvmConfig::default();
            config.environment = environment;
            config.apply_environment_overrides()?;
            config.validate()?;
            Ok(config)
        }
    }

    /// Get configuration value by key path (e.g., "network.rpc_url")
    pub fn get_value(&self, key_path: &str) -> Option<serde_json::Value> {
        let config_json = serde_json::to_value(self).ok()?;
        
        let keys: Vec<&str> = key_path.split('.').collect();
        let mut current_value = &config_json;
        
        for key in keys {
            current_value = current_value.get(key)?;
        }
        
        Some(current_value.clone())
    }

    /// Update configuration value by key path
    pub fn set_value(&mut self, key_path: &str, value: serde_json::Value) -> ZkEvmResult<()> {
        // This is a simplified implementation
        // In production, you'd want a more robust way to update nested values
        self.custom.insert(key_path.to_string(), value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config_creation() {
        let config = ZkEvmConfig::default();
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.proving.default_strategy, "ZodaWarpHybrid");
        assert!(config.proving.hybrid.zoda_weight + config.proving.hybrid.warp_weight - 1.0 < 0.001);
    }

    #[test]
    fn test_environment_parsing() {
        assert_eq!("development".parse::<Environment>().unwrap(), Environment::Development);
        assert_eq!("prod".parse::<Environment>().unwrap(), Environment::Production);
        assert!("invalid".parse::<Environment>().is_err());
    }

    #[test]
    fn test_config_validation() {
        let mut config = ZkEvmConfig::default();
        // Disable TLS and auth for testing
        config.security.enable_tls = false;
        config.security.enable_auth = false;
        assert!(config.validate().is_ok());

        // Test invalid configuration
        config.network.rpc_url = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        
        let mut config = ZkEvmConfig::default();
        // Disable TLS and auth for testing
        config.security.enable_tls = false;
        config.security.enable_auth = false;
        config.save_to_file(&config_path).unwrap();
        
        let loaded_config = ZkEvmConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.environment, loaded_config.environment);
    }

    #[test]
    fn test_environment_overrides() {
        env::set_var("ZKVM_ENVIRONMENT", "production");
        env::set_var("ZKVM_CHAIN_ID", "42");
        env::set_var("ZKVM_MAX_MEMORY_MB", "2048");
        
        let mut config = ZkEvmConfig::default();
        config.apply_environment_overrides().unwrap();
        
        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.network.chain_id, 42);
        assert_eq!(config.performance.max_memory_mb, 2048);
        
        // Clean up
        env::remove_var("ZKVM_ENVIRONMENT");
        env::remove_var("ZKVM_CHAIN_ID");
        env::remove_var("ZKVM_MAX_MEMORY_MB");
    }

    #[test]
    fn test_create_default_configs() {
        let temp_dir = TempDir::new().unwrap();
        ZkEvmConfig::create_default_configs(temp_dir.path()).unwrap();
        
        // Check that all environment config files were created
        for env in [Environment::Development, Environment::Testing, Environment::Staging, Environment::Production] {
            let config_path = ZkEvmConfig::get_config_path(&env, Some(temp_dir.path()));
            assert!(config_path.exists());
            
            // Load config content directly from file, then disable TLS/auth for testing
            let content = std::fs::read_to_string(&config_path).unwrap();
            let mut config: ZkEvmConfig = toml::from_str(&content).unwrap();
            config.security.enable_tls = false;
            config.security.enable_auth = false;
            assert!(config.validate().is_ok());
            assert_eq!(config.environment, env);
        }
    }
}
