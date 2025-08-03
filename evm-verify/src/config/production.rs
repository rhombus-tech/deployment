// ZODA Production Configuration Management System
//
// Environment-specific configuration with validation and hot-reloading

use std::time::Duration;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, Environment, File};

/// Master configuration for ZODA-WARP system
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ZodaConfig {
    /// Network and RPC configuration
    pub network: NetworkConfig,
    
    /// Core proving system configuration
    pub proving: ProvingConfig,
    
    /// Performance optimization settings
    pub performance: PerformanceConfig,
    
    /// Monitoring and observability configuration
    pub monitoring: MonitoringConfig,
    
    /// Security and compliance settings
    pub security: SecurityConfig,
    
    /// Storage and persistence configuration
    pub storage: StorageConfig,
    
    /// API and service configuration
    pub api: ApiConfig,
    
    /// Environment-specific overrides
    pub environment: EnvironmentConfig,
}

/// Network and Ethereum RPC configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NetworkConfig {
    /// Primary Ethereum RPC endpoint URL
    pub ethereum_rpc_url: String,
    
    /// Backup RPC endpoints for failover
    pub backup_rpc_urls: Vec<String>,
    
    /// Ethereum chain ID (1 for mainnet, 5 for Goerli, etc.)
    pub chain_id: u64,
    
    /// Maximum acceptable block lag behind network head
    pub max_block_lag: u64,
    
    /// Network request timeout in seconds
    pub timeout_seconds: u64,
    
    /// Maximum concurrent RPC requests
    pub max_concurrent_requests: usize,
    
    /// Rate limiting: requests per second
    pub rate_limit_rps: u32,
    
    /// WebSocket RPC endpoint for real-time updates
    pub websocket_url: Option<String>,
    
    /// Enable/disable mainnet block validation
    pub enable_mainnet_validation: bool,
}

/// Core ZODA-WARP proving system configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProvingConfig {
    /// Tensor encoding dimensions (rows, columns)
    pub tensor_dimensions: (usize, usize),
    
    /// Reed-Solomon sampling rate for error correction
    pub sampling_rate: usize,
    
    /// Maximum acceptable proof size in bytes
    pub max_proof_size: usize,
    
    /// Minimum syndrome verification success threshold (0.0-1.0)
    pub verification_threshold: f64,
    
    /// Enable advanced vulnerability detection in circuits
    pub enable_vulnerability_detection: bool,
    
    /// WARP accumulation batch size
    pub warp_batch_size: usize,
    
    /// Maximum circuits to accumulate in single batch
    pub max_batch_circuits: usize,
    
    /// Proof compression level (1-9, higher = more compression)
    pub compression_level: u8,
    
    /// Enable parallel proving across multiple cores
    pub enable_parallel_proving: bool,
    
    /// Cryptographic randomness source
    pub randomness_source: RandomnessSource,
}

/// Performance optimization configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceConfig {
    /// Number of worker threads for parallel operations
    pub worker_threads: usize,
    
    /// Circuit processing batch size
    pub batch_size: usize,
    
    /// Maximum memory usage limit in MB
    pub memory_limit_mb: usize,
    
    /// Tensor computation cache size
    pub cache_size: usize,
    
    /// Enable CPU performance optimizations
    pub enable_cpu_optimizations: bool,
    
    /// Enable memory pool for faster allocations
    pub enable_memory_pool: bool,
    
    /// Garbage collection frequency (operations between GC)
    pub gc_frequency: usize,
    
    /// Background task processing interval
    pub background_task_interval_ms: u64,
    
    /// Circuit preprocessing pipeline depth
    pub preprocessing_pipeline_depth: usize,
}

/// Monitoring and observability configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MonitoringConfig {
    /// Enable Prometheus metrics export
    pub enable_prometheus: bool,
    
    /// Prometheus metrics server bind address
    pub prometheus_bind_address: String,
    
    /// Metrics collection interval in seconds
    pub metrics_interval_seconds: u64,
    
    /// Enable health check endpoint
    pub enable_health_checks: bool,
    
    /// Health check endpoint bind address
    pub health_check_bind_address: String,
    
    /// Log configuration
    pub logging: crate::logging::production::LogConfig,
    
    /// Enable performance profiling
    pub enable_profiling: bool,
    
    /// Profiling data collection interval
    pub profiling_interval_seconds: u64,
    
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Security and compliance configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    /// Enable circuit input validation
    pub enable_input_validation: bool,
    
    /// Maximum circuit complexity allowed
    pub max_circuit_complexity: usize,
    
    /// Enable timing attack protection
    pub enable_timing_protection: bool,
    
    /// Cryptographic security level (128, 192, 256 bits)
    pub security_level_bits: u16,
    
    /// Enable formal verification checks
    pub enable_formal_verification: bool,
    
    /// Audit logging configuration
    pub audit_logging: AuditConfig,
    
    /// Rate limiting for API endpoints
    pub api_rate_limits: ApiRateLimit,
}

/// Storage and persistence configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StorageConfig {
    /// Base directory for data storage
    pub data_directory: PathBuf,
    
    /// Enable proof caching to disk
    pub enable_proof_cache: bool,
    
    /// Proof cache size limit in MB
    pub proof_cache_size_mb: usize,
    
    /// Circuit cache configuration
    pub circuit_cache_size_mb: usize,
    
    /// Database configuration for persistent storage
    pub database: Option<DatabaseConfig>,
    
    /// Backup configuration
    pub backup: BackupConfig,
}

/// API and service configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiConfig {
    /// HTTP API server bind address
    pub bind_address: String,
    
    /// Enable CORS for web clients
    pub enable_cors: bool,
    
    /// Allowed CORS origins
    pub cors_origins: Vec<String>,
    
    /// API request timeout in seconds
    pub request_timeout_seconds: u64,
    
    /// Maximum request body size in bytes
    pub max_request_size_bytes: usize,
    
    /// Enable API key authentication
    pub enable_api_key_auth: bool,
    
    /// API versioning configuration
    pub api_version: String,
    
    /// Enable gRPC service
    pub enable_grpc: bool,
    
    /// gRPC service bind address
    pub grpc_bind_address: Option<String>,
}

/// Environment-specific configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EnvironmentConfig {
    /// Environment name (development, staging, production)
    pub environment_name: String,
    
    /// Enable development-only features
    pub enable_dev_features: bool,
    
    /// Enable debug endpoints
    pub enable_debug_endpoints: bool,
    
    /// Strict mode for production environments
    pub strict_mode: bool,
    
    /// Feature flags
    pub feature_flags: FeatureFlags,
}

/// Randomness source for cryptographic operations
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum RandomnessSource {
    /// System random number generator
    SystemRng,
    /// Hardware random number generator
    HardwareRng,
    /// Deterministic for testing
    Deterministic { seed: u64 },
}

/// Alert threshold configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlertThresholds {
    /// CPU usage percentage threshold
    pub cpu_usage_percent: f64,
    
    /// Memory usage percentage threshold  
    pub memory_usage_percent: f64,
    
    /// Error rate threshold (errors per second)
    pub error_rate_threshold: f64,
    
    /// Proof generation latency threshold in milliseconds
    pub latency_threshold_ms: u64,
    
    /// Syndrome validation success rate threshold
    pub syndrome_success_threshold: f64,
}

/// Audit logging configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    
    /// Audit log file path
    pub log_file_path: PathBuf,
    
    /// Events to audit
    pub audit_events: Vec<AuditEvent>,
}

/// API rate limiting configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiRateLimit {
    /// Requests per minute per IP
    pub requests_per_minute: u32,
    
    /// Burst limit for short-term requests
    pub burst_limit: u32,
    
    /// Enable rate limiting
    pub enabled: bool,
}

/// Database configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DatabaseConfig {
    /// Database connection URL
    pub connection_url: String,
    
    /// Maximum database connections
    pub max_connections: u32,
    
    /// Connection timeout
    pub connection_timeout_seconds: u64,
}

/// Backup configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub enabled: bool,
    
    /// Backup directory
    pub backup_directory: PathBuf,
    
    /// Backup frequency in hours
    pub backup_frequency_hours: u64,
    
    /// Number of backups to retain
    pub backup_retention_count: usize,
}

/// Feature flags for experimental features
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FeatureFlags {
    /// Enable experimental tensor optimizations
    pub enable_experimental_tensors: bool,
    
    /// Enable new WARP accumulation algorithm
    pub enable_warp_v2: bool,
    
    /// Enable parallel verification
    pub enable_parallel_verification: bool,
    
    /// Enable circuit preprocessing cache
    pub enable_circuit_cache: bool,
}

/// Events to audit in security logging
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum AuditEvent {
    ProofGeneration,
    CircuitValidation,
    ApiAccess,
    ConfigurationChange,
    SecurityViolation,
}

impl Default for ZodaConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            proving: ProvingConfig::default(),
            performance: PerformanceConfig::default(),
            monitoring: MonitoringConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            api: ApiConfig::default(),
            environment: EnvironmentConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ethereum_rpc_url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY".to_string(),
            backup_rpc_urls: vec![
                "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
                "https://rpc.ankr.com/eth".to_string(),
            ],
            chain_id: 1,
            max_block_lag: 10,
            timeout_seconds: 30,
            max_concurrent_requests: 10,
            rate_limit_rps: 50,
            websocket_url: None,
            enable_mainnet_validation: true,
        }
    }
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            tensor_dimensions: (32, 16),
            sampling_rate: 4,
            max_proof_size: 300_000, // 300KB - Ethereum L1 limit
            verification_threshold: 0.95,
            enable_vulnerability_detection: true, // Security-first L1 zkEVM approach
            warp_batch_size: 10,
            max_batch_circuits: 100,
            compression_level: 6,
            enable_parallel_proving: true,
            randomness_source: RandomnessSource::SystemRng,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            batch_size: 10,
            memory_limit_mb: 4096, // 4GB
            cache_size: 1000,
            enable_cpu_optimizations: true,
            enable_memory_pool: true,
            gc_frequency: 1000,
            background_task_interval_ms: 1000,
            preprocessing_pipeline_depth: 3,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            prometheus_bind_address: "127.0.0.1:9090".to_string(),
            metrics_interval_seconds: 10,
            enable_health_checks: true,
            health_check_bind_address: "127.0.0.1:8080".to_string(),
            logging: crate::logging::production::LogConfig::default(),
            enable_profiling: false,
            profiling_interval_seconds: 60,
            alert_thresholds: AlertThresholds::default(),
        }
    }
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 80.0,
            memory_usage_percent: 85.0,
            error_rate_threshold: 5.0,
            latency_threshold_ms: 1000,
            syndrome_success_threshold: 0.90,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_input_validation: true,
            max_circuit_complexity: 1_000_000,
            enable_timing_protection: true,
            security_level_bits: 256,
            enable_formal_verification: false,
            audit_logging: AuditConfig::default(),
            api_rate_limits: ApiRateLimit::default(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file_path: PathBuf::from("./logs/audit.log"),
            audit_events: vec![
                AuditEvent::ProofGeneration,
                AuditEvent::CircuitValidation,
                AuditEvent::ApiAccess,
                AuditEvent::SecurityViolation,
            ],
        }
    }
}

impl Default for ApiRateLimit {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            burst_limit: 20,
            enabled: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_directory: PathBuf::from("./data"),
            enable_proof_cache: true,
            proof_cache_size_mb: 1024, // 1GB
            circuit_cache_size_mb: 512, // 512MB
            database: None,
            backup: BackupConfig::default(),
        }
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backup_directory: PathBuf::from("./backups"),
            backup_frequency_hours: 24,
            backup_retention_count: 7,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:3000".to_string(),
            enable_cors: true,
            cors_origins: vec!["*".to_string()],
            request_timeout_seconds: 30,
            max_request_size_bytes: 10_000_000, // 10MB
            enable_api_key_auth: false,
            api_version: "v1".to_string(),
            enable_grpc: false,
            grpc_bind_address: None,
        }
    }
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            environment_name: "development".to_string(),
            enable_dev_features: true,
            enable_debug_endpoints: true,
            strict_mode: false,
            feature_flags: FeatureFlags::default(),
        }
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            enable_experimental_tensors: false,
            enable_warp_v2: false,
            enable_parallel_verification: true,
            enable_circuit_cache: true,
        }
    }
}

impl ZodaConfig {
    /// Load configuration from files and environment variables
    pub fn load() -> Result<Self, ConfigError> {
        let environment = std::env::var("ZODA_ENV").unwrap_or_else(|_| "development".into());
        
        let settings = Config::builder()
            // Start with default configuration
            .add_source(File::with_name("config/default").required(false))
            
            // Add environment-specific configuration
            .add_source(File::with_name(&format!("config/{}", environment)).required(false))
            
            // Add local configuration overrides (not in version control)
            .add_source(File::with_name("config/local").required(false))
            
            // Add environment variables with prefix ZODA_
            // Example: ZODA_NETWORK__ETHEREUM_RPC_URL
            .add_source(Environment::with_prefix("ZODA").separator("__"))
            
            .build()?;
        
        let mut config: ZodaConfig = settings.try_deserialize()?;
        
        // Apply environment-specific adjustments
        config.apply_environment_adjustments(&environment);
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }
    
    /// Apply environment-specific configuration adjustments
    fn apply_environment_adjustments(&mut self, environment: &str) {
        self.environment.environment_name = environment.to_string();
        
        match environment {
            "production" => {
                self.environment.enable_dev_features = false;
                self.environment.enable_debug_endpoints = false;
                self.environment.strict_mode = true;
                self.security.enable_formal_verification = true;
                self.monitoring.enable_profiling = false;
                self.monitoring.logging = crate::logging::production::create_log_config_for_env("production");
            }
            
            "staging" => {
                self.environment.enable_dev_features = false;
                self.environment.enable_debug_endpoints = true;
                self.environment.strict_mode = true;
                self.monitoring.enable_profiling = true;
                self.monitoring.logging = crate::logging::production::create_log_config_for_env("staging");
            }
            
            "development" => {
                self.environment.enable_dev_features = true;
                self.environment.enable_debug_endpoints = true;
                self.environment.strict_mode = false;
                self.monitoring.enable_profiling = true;
                self.monitoring.logging = crate::logging::production::create_log_config_for_env("development");
            }
            
            _ => {} // Keep defaults
        }
    }
    
    /// Validate configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate network configuration
        if self.network.ethereum_rpc_url.is_empty() {
            return Err(ConfigError::Message("ethereum_rpc_url cannot be empty".into()));
        }
        
        if self.network.chain_id == 0 {
            return Err(ConfigError::Message("chain_id must be greater than 0".into()));
        }
        
        // Validate proving configuration
        if self.proving.tensor_dimensions.0 == 0 || self.proving.tensor_dimensions.1 == 0 {
            return Err(ConfigError::Message("tensor_dimensions must be greater than 0".into()));
        }
        
        if self.proving.verification_threshold < 0.0 || self.proving.verification_threshold > 1.0 {
            return Err(ConfigError::Message("verification_threshold must be between 0.0 and 1.0".into()));
        }
        
        // Validate performance configuration
        if self.performance.worker_threads == 0 {
            return Err(ConfigError::Message("worker_threads must be greater than 0".into()));
        }
        
        if self.performance.memory_limit_mb < 512 {
            return Err(ConfigError::Message("memory_limit_mb must be at least 512MB".into()));
        }
        
        // Validate security configuration
        if ![128, 192, 256].contains(&self.security.security_level_bits) {
            return Err(ConfigError::Message("security_level_bits must be 128, 192, or 256".into()));
        }
        
        Ok(())
    }
    
    /// Get configuration optimized for specific hardware
    pub fn optimize_for_hardware(&mut self) {
        let cpu_count = num_cpus::get();
        let total_memory = sys_info::mem_info().map(|info| info.total).unwrap_or(4_000_000) / 1024; // MB
        
        // Optimize worker threads
        self.performance.worker_threads = std::cmp::max(1, cpu_count);
        
        // Optimize memory usage (use up to 75% of available memory)
        let optimal_memory = (total_memory as f64 * 0.75) as usize;
        if optimal_memory > self.performance.memory_limit_mb {
            self.performance.memory_limit_mb = optimal_memory;
        }
        
        // Optimize cache sizes based on available memory
        self.storage.proof_cache_size_mb = std::cmp::min(
            self.storage.proof_cache_size_mb,
            self.performance.memory_limit_mb / 4
        );
        
        self.storage.circuit_cache_size_mb = std::cmp::min(
            self.storage.circuit_cache_size_mb,
            self.performance.memory_limit_mb / 8
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_validation() {
        let config = ZodaConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test] 
    fn test_environment_adjustments() {
        let mut config = ZodaConfig::default();
        config.apply_environment_adjustments("production");
        
        assert!(!config.environment.enable_dev_features);
        assert!(!config.environment.enable_debug_endpoints);
        assert!(config.environment.strict_mode);
    }
    
    #[test]
    fn test_hardware_optimization() {
        let mut config = ZodaConfig::default();
        config.optimize_for_hardware();
        
        assert!(config.performance.worker_threads > 0);
        assert!(config.performance.memory_limit_mb >= 512);
    }
}
