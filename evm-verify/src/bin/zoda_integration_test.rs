// ZODA Integration Test CLI
//
// This binary runs the ZODA integration tests to verify end-to-end functionality
// between the Rust ZODA proof generation and the deployed smart contracts.

use anyhow::Result;
use clap::Parser;
use log::{info, error};

#[cfg(feature = "integration-tests")]
use evm_verify::integration_test::ZODAIntegrationTest;

#[derive(Parser)]
#[clap(name = "zoda-integration-test")]
#[clap(about = "Run ZODA integration tests against deployed smart contracts")]
struct Args {
    /// RPC URL for the blockchain (defaults to local testnet)
    #[clap(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    
    /// Run only specific test by name
    #[clap(long)]
    test: Option<String>,
    
    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    
    info!("🚀 Starting ZODA Integration Test Suite");
    info!("RPC URL: {}", args.rpc_url);
    
    #[cfg(feature = "integration-tests")]
    {
        // Create integration test instance
        let test = ZODAIntegrationTest::new().await?;
        
        match args.test.as_deref() {
            Some("generate") => {
                info!("Running proof generation test only");
                let (proof_hash, proof_data) = test.test_generate_zoda_proof().await?;
                info!("✅ Proof generation completed successfully");
                info!("Proof hash: 0x{}", hex::encode(&proof_hash));
                info!("Proof data size: {} bytes", proof_data.len());
            }
            Some("verify") => {
                info!("Running on-chain verification test");
                let (proof_hash, proof_data) = test.test_generate_zoda_proof().await?;
                let result = test.test_on_chain_verification(proof_hash, proof_data).await?;
                if result {
                    info!("✅ On-chain verification passed");
                } else {
                    error!("❌ On-chain verification failed");
                    std::process::exit(1);
                }
            }
            Some("atomic") => {
                info!("Running atomic execution test");
                let (proof_hash, _) = test.test_generate_zoda_proof().await?;
                test.test_atomic_execution_with_proof(proof_hash).await?;
                info!("✅ Atomic execution test completed");
            }
            Some(name) => {
                error!("Unknown test name: {}", name);
                std::process::exit(1);
            }
            None => {
                info!("Running full test suite");
                test.run_full_test_suite().await?;
                info!("🎉 All tests completed successfully!");
            }
        }
    }
    
    #[cfg(not(feature = "integration-tests"))]
    {
        error!("Integration tests are not enabled. Please compile with --features integration-tests");
        std::process::exit(1);
    }
    
    Ok(())
}
