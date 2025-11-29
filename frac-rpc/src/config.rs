use serde::{Deserialize, Serialize};
use std::env;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FracRPCConfig {
    pub server: ServerConfig,
    pub nodes: NodesConfig,
    pub cache: CacheConfig,
    pub proving: ProvingConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodesConfig {
    pub primary: Vec<NodeConfig>,
    pub fallback: Vec<NodeConfig>,
    pub health_check_interval_secs: u64,
    pub request_timeout_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub url: String,
    pub node_type: NodeType,
    pub weight: f64, // For load balancing
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Erigon,
    Geth,
    External, // Alchemy, Infura, etc.
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    pub redis_url: String,
    pub ttl_secs: u64,
    pub max_memory_mb: usize,
    pub enable_compression: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvingConfig {
    // Cache commonly requested blocks for proving
    pub hot_block_range: u64, // Last N blocks to keep in hot cache
    pub batch_size: usize,     // Max blocks per batch request
    pub prefetch_enabled: bool, // Prefetch next blocks provers will need
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enable_metrics: bool,
    pub enable_tracing: bool,
    pub log_level: String,
}

impl FracRPCConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenv::dotenv().ok();

        Ok(Self {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8545".to_string())
                    .parse()?,
                workers: env::var("SERVER_WORKERS")
                    .unwrap_or_else(|_| num_cpus::get().to_string())
                    .parse()?,
            },
            nodes: NodesConfig {
                primary: vec![
                    NodeConfig {
                        name: "erigon-primary".to_string(),
                        url: env::var("ERIGON_PRIMARY_URL")
                            .unwrap_or_else(|_| "http://localhost:8545".to_string()),
                        node_type: NodeType::Erigon,
                        weight: 0.7,
                    },
                    NodeConfig {
                        name: "erigon-secondary".to_string(),
                        url: env::var("ERIGON_SECONDARY_URL")
                            .unwrap_or_else(|_| "http://localhost:8546".to_string()),
                        node_type: NodeType::Erigon,
                        weight: 0.3,
                    },
                ],
                fallback: vec![
                    NodeConfig {
                        name: "alchemy".to_string(),
                        url: env::var("ALCHEMY_URL")
                            .unwrap_or_else(|_| "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY".to_string()),
                        node_type: NodeType::External,
                        weight: 0.6,
                    },
                    NodeConfig {
                        name: "infura".to_string(),
                        url: env::var("INFURA_URL")
                            .unwrap_or_else(|_| "https://mainnet.infura.io/v3/YOUR_KEY".to_string()),
                        node_type: NodeType::External,
                        weight: 0.4,
                    },
                ],
                health_check_interval_secs: 30,
                request_timeout_secs: 10,
            },
            cache: CacheConfig {
                redis_url: env::var("REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                ttl_secs: 300, // 5 minutes default
                max_memory_mb: 2048, // 2GB
                enable_compression: true,
            },
            proving: ProvingConfig {
                hot_block_range: 1000, // Keep last 1000 blocks hot
                batch_size: 100,
                prefetch_enabled: true,
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                enable_tracing: true,
                log_level: env::var("LOG_LEVEL")
                    .unwrap_or_else(|_| "info".to_string()),
            },
        })
    }
}
