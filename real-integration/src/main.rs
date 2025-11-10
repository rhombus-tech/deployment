// Example usage of the real integration layer

use real_integration::*;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting Real Integration Layer Example");
    
    let config = BlockchainConfig {
        tee_config: TEEConfig {
            controller_binary_path: "./bin/hyper-tee-controller".to_string(),
            coordinator_url: "https://tee-mesh.example.com".to_string(),
            region_id: "us-west-2".to_string(),
            tee_type: "SGX".to_string(),
            execution_mode: "mesh".to_string(),
        },
        zkevm_config: ZKEVMConfig {
            binary_path: "./bin/zkvm-prover".to_string(),
            config_path: "./config/zkvm.toml".to_string(),
            verification_level: "production".to_string(),
        },
        stateless_config: StatelessVMConfig {
            binary_path: "./bin/stateless-vm".to_string(),
            config_path: "./config/stateless.toml".to_string(),
            cache_enabled: true,
        },
        ethereum_config: EthereumBridgeConfig {
            service_url: "https://eth-bridge.example.com".to_string(),
            contract_address: "0x742d35Cc6634C0532925a3b8D6C3C48c5EE3c9c".to_string(),
            rpc_url: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string(),
            private_key_path: "/secrets/eth_private_key".to_string(),
        },
        avalanche_config: AvalancheBridgeConfig {
            service_url: "https://avax-bridge.example.com".to_string(),
            region_id: "us-west-2".to_string(),
            rlnc_enabled: true,
        },
    };
    
    let blockchain = RealTEEMeshBlockchain::new(config).await?;
    
    println!("✅ Real TEE Mesh Blockchain initialized successfully");
    println!("📊 Ready to process transactions through real infrastructure");
    
    // Get system metrics
    match blockchain.get_system_metrics().await {
        Ok(metrics) => {
            println!("🔍 System Metrics:");
            println!("  - Active TEE peers: {}", metrics.mesh_status.active_peers);
            println!("  - Total transactions processed: {}", metrics.total_transactions_processed);
            println!("  - Ethereum batches: {}", metrics.ethereum_metrics.total_batches);
            println!("  - Avalanche latency: {}ms", metrics.avalanche_metrics.avg_latency_ms);
        }
        Err(e) => {
            println!("⚠️  Could not retrieve metrics (services may not be running): {}", e);
        }
    }
    
    println!("🎯 Real integration layer ready for production use!");
    
    Ok(())
}
