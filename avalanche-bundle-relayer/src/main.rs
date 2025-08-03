mod api;
mod bundle;
mod config;
mod errors;
mod types;
mod statelessvm;

use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use tokio::signal;
use log::{info, error};
use clap::{App, Arg};

use crate::api::rest::setup_rest_api;
use crate::api::websocket::setup_websocket_api;
use crate::bundle::{BundleValidator, DefaultBundleValidator};
use crate::config::Config;
use crate::errors::{Result, RelayerError};
use crate::types::{BundleId, BundleStatus, TransactionBundle};
use crate::bundle::BundleManager;
use crate::statelessvm::StatelessVmClient;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = App::new("Avalanche Bundle Relayer")
        .version("0.1.0")
        .author("Avalanche Team")
        .about("Relays transaction bundles to Avalanche StatelessVM")
        .arg(Arg::with_name("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file path")
            .takes_value(true))
        .arg(Arg::with_name("verbose")
            .short('v')
            .long("verbose")
            .help("Enables verbose logging")
            .takes_value(false))
        .get_matches();

    // Setup logging
    let log_level = if matches.is_present("verbose") {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    // Load configuration
    let config_path = matches.value_of("config")
        .unwrap_or("config.toml");

    let config = match Config::from_file(config_path) {
        Ok(config) => {
            info!("Configuration loaded successfully from {}", config_path);
            config
        },
        Err(e) => {
            error!("Failed to load configuration from {}: {}", config_path, e);
            return Err(RelayerError::ConfigError(format!("Failed to load config: {}", e)));
        }
    };

    // Initialize shared state
    let bundles: Arc<Mutex<HashMap<BundleId, TransactionBundle>>> = Arc::new(Mutex::new(HashMap::new()));
    let statuses: Arc<Mutex<HashMap<BundleId, BundleStatus>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // Initialize validator
    let validator = Arc::new(DefaultBundleValidator::new(
        config.security.clone(),
        config.chain.chain_id,
        config.security.max_bundle_size,
        10_000_000 // Default max transaction size
    )) as Arc<dyn BundleValidator>;
    
    // Initialize StatelessVM client
    let stateless_vm = StatelessVmClient::new(config.statelessvm.clone());

    // Initialize bundle manager
    let bundle_manager = BundleManager::new(config.clone(), validator.clone(), stateless_vm).await
        .map_err(|e| {
            error!("Failed to initialize bundle manager: {}", e);
            RelayerError::InitializationError(format!("Failed to initialize bundle manager: {}", e))
        })?;
    let bundle_manager = Arc::new(bundle_manager);

    // Setup REST API server
    let rest_api_handle = setup_rest_api(
        config.server.rest_port, 
        config.server.api_keys.clone(), 
        bundles.clone(), 
        statuses.clone(),
        validator.clone()
    ).await;

    // Setup WebSocket API server
    let websocket_api_handle = setup_websocket_api(
        config.server.ws_port,
        config.server.api_keys.clone(),
        statuses.clone()
    );

    info!("Avalanche Bundle Relayer started successfully!");
    info!("REST API running on port {}", config.server.rest_port);
    info!("WebSocket API running on port {}", config.server.ws_port);

    // Wait for termination signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal. Shutting down gracefully...");
        },
        Err(e) => {
            error!("Failed to listen for shutdown signal: {}", e);
        }
    }

    // Clean up and shutdown
    info!("Shutting down API servers...");
    drop(rest_api_handle);
    drop(websocket_api_handle);
    info!("Shutdown complete!");

    Ok(())
}
