// Configuration handling for the bundle relayer

use std::path::Path;
use std::fs;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};
use anyhow::{Result as AnyhowResult, Context};
use crate::errors::{Result, RelayerError};
use crate::types::SecurityConfig;

/// RPC URL type for chain connections
pub type RpcUrl = String;

/// Config type alias for main RelayerConfig
pub type Config = RelayerConfig;

/// Main configuration for the bundle relayer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Chain configuration
    pub chain: ChainConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// API configuration
    pub api: ApiConfig,
    /// StatelessVM configuration
    pub statelessvm: StatelessVmConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host address to bind to
    pub host: String,
    /// REST API port
    pub rest_port: u16,
    /// WebSocket API port
    pub ws_port: u16,
    /// Whether to use authentication for API endpoints
    pub auth_required: bool,
    /// API keys
    pub api_keys: Vec<String>,
    /// Log level
    pub log_level: String,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database path
    pub path: String,
    /// Maximum connections
    pub max_connections: Option<u32>,
}

/// Chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,
    /// RPC URL
    pub rpc_url: String,
    /// WebSocket URL (optional)
    pub ws_url: Option<String>,
    /// Number of confirmations required for finality
    pub required_confirmations: u64,
    /// Gas price multiplier for bundle transactions
    pub gas_price_multiplier: f64,
    /// Gas limit for bundle simulation
    pub simulation_gas_limit: u64,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable bundle submission endpoint
    pub enable_submit: bool,
    /// Enable bundle status endpoint
    pub enable_status: bool,
    /// Enable metrics endpoint
    pub enable_metrics: bool,
    /// CORS allow origin
    pub cors_allow_origin: String,
    /// Maximum request body size (in bytes)
    pub max_body_size: usize,
    /// Request timeout (in seconds)
    pub request_timeout: u64,
    /// Bundle processing timeout (in seconds)
    pub bundle_timeout_seconds: u64,
}

/// StatelessVM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessVmConfig {
    /// StatelessVM API endpoint URL
    pub endpoint_url: String,
    /// Timeout for StatelessVM API calls (in seconds)
    pub timeout_seconds: u64,
    /// Maximum number of retries for API calls
    pub max_retries: u32,
    /// Whether to validate execution traces
    pub validate_traces: bool,
}

impl RelayerConfig {
    /// Socket address for server binding (REST API)
    pub fn rest_socket_addr(&self) -> SocketAddr {
        format!("{0}:{1}", self.server.host, self.server.rest_port)
            .parse()
            .expect("Invalid socket address")
    }
    
    /// WebSocket address for server binding
    pub fn ws_socket_addr(&self) -> SocketAddr {
        format!("{0}:{1}", self.server.host, self.server.ws_port)
            .parse()
            .expect("Invalid socket address")
    }
    
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| RelayerError::ConfigError(format!("Failed to read config file: {}", e)))?;
            
        let config: RelayerConfig = toml::from_str(&content)
            .map_err(|e| RelayerError::ConfigError(format!("Failed to parse config: {}", e)))?;
            
        Ok(config)
    }
    
    /// Create default configuration
    pub fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                rest_port: 8080,
                ws_port: 8081,
                auth_required: false,
                api_keys: vec![],
                log_level: "info".to_string(),
            },
            chain: ChainConfig {
                rpc_url: "http://localhost:8545".to_string(),
                chain_id: 43112, // Default for Avalanche local
                ws_url: None,
                required_confirmations: 3,
                gas_price_multiplier: 1.5,
                simulation_gas_limit: 10000000,
            },
            security: SecurityConfig {
                validation_level: crate::types::SecurityValidationLevel::Standard,
                max_bundle_gas: 10000000,
                max_bundle_size: 50,
                verification_mode: "always".to_string(),
            },
            database: DatabaseConfig {
                path: "./data/relayer.db".to_string(),
                max_connections: Some(10),
            },
            api: ApiConfig {
                enable_submit: true,
                enable_status: true,
                enable_metrics: true,
                cors_allow_origin: "*".to_string(),
                max_body_size: 1024 * 100, // 100 KB
                request_timeout: 60,
                bundle_timeout_seconds: 60,
            },
            statelessvm: StatelessVmConfig {
                endpoint_url: "http://localhost:8090".to_string(),
                timeout_seconds: 30,
                max_retries: 3,
                validate_traces: true,
            },
        }
    }
}

/// Write default configuration to a file
pub fn write_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
    let config = RelayerConfig::default();
    let content = toml::to_string_pretty(&config)
        .map_err(|e| RelayerError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
    fs::write(path, content)
        .map_err(|e| RelayerError::ConfigError(format!("Failed to write config file: {}", e)))?;
        
    Ok(())
}
