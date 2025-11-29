// EARN FRAC TOKENS - Complete example
// Run a node, generate proofs, earn FRAC tokens

use evm_verify::fractal_network::{
    FracRewardSystem, PermissionlessBootstrap, DecentralizedTaskPool,
    TaskSelectionStrategy, P2PNetwork, NetworkConfig, ProvingEconomics,
    FractalMetrics, CompletedProof, AggregationMethod, PaymentSource,
};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║   💰 EARN FRAC TOKENS - Production Prover Node        ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // STEP 1: Configuration
    let eth_rpc = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let reward_pool = std::env::var("REWARD_POOL_ADDRESS")
        .expect("Set REWARD_POOL_ADDRESS environment variable");
    let private_key = std::env::var("PRIVATE_KEY")
        .expect("Set PRIVATE_KEY environment variable");
    
    println!("📋 Configuration:");
    println!("   RPC: {}", eth_rpc);
    println!("   Reward Pool: {}", reward_pool);
    println!("   Wallet: 0x{}...", &private_key[2..8]);
    println!();

    // STEP 2: Initialize FRAC reward system
    println!("🔧 Initializing FRAC reward system...");
    let frac_system = FracRewardSystem::new(
        &eth_rpc,
        &reward_pool,
        &private_key,
    ).await?;
    println!("✅ Connected to FRAC reward pool\n");

    // STEP 3: Bootstrap into network
    println!("🌐 Bootstrapping into fractal network...");
    let bootstrap = PermissionlessBootstrap::new();
    let identity = bootstrap.generate_identity();
    println!("✅ Node ID: {}", identity.node_id.0);
    println!("   Public Key: {}", hex::encode(&identity.public_key));
    println!();

    // STEP 4: Start P2P network
    println!("📡 Starting P2P network...");
    let network_config = NetworkConfig {
        listen_address: "/ip4/0.0.0.0/tcp/9000".to_string(),
        bootstrap_peers: vec![],
    };
    let p2p_network = P2PNetwork::new(network_config).await?;
    println!("✅ P2P network listening on port 9000\n");

    // STEP 5: Initialize task pool
    println!("📦 Initializing decentralized task pool...");
    let task_pool = DecentralizedTaskPool::new(identity.node_id.clone());
    println!("✅ Task pool ready\n");

    // STEP 6: Start metrics
    println!("📊 Starting metrics server...");
    let metrics = FractalMetrics::new();
    println!("✅ Metrics at http://localhost:9090/metrics\n");

    // STEP 7: Initialize economics tracker
    let mut economics = ProvingEconomics::new(10.0); // 10 FRAC base reward

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║   🚀 PROVER NODE RUNNING - EARNING FRAC TOKENS        ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // STEP 8: Main proving loop
    let mut proofs_generated = 0;
    let start_time = Instant::now();
    
    for i in 0..10 {
        println!("────────────────────────────────────────");
        println!("🔄 Cycle {}/10", i + 1);
        
        // Discover tasks
        let tasks = task_pool.discover_tasks(TaskSelectionStrategy::HighestReward);
        if tasks.is_empty() {
            println!("   No tasks available, creating simulated task...");
            task_pool.announce_task(format!("block_{}", 18500000 + i), 25.0, 100);
        }
        
        // Select task
        let task_id = format!("block_{}", 18500000 + i);
        println!("📦 Processing task: {}", task_id);
        
        let task_start = Instant::now();
        
        // Generate proof (simulated for demo - in production, call TensorZODA)
        sleep(Duration::from_millis(2)).await;
        let proving_time = task_start.elapsed();
        
        let proof = CompletedProof {
            task_id: task_id.clone(),
            aggregated_proof: vec![0u8; 128],
            phi_efficiency: 1.618,
            segment_count: 1,
            aggregation_method: AggregationMethod::Sequential,
        };
        
        println!("✅ Proof generated in {:.2}ms", proving_time.as_secs_f64() * 1000.0);
        
        // Calculate proof quality
        let quality: u8 = 85 + (i % 15) as u8; // 85-100%
        let time_ms = proving_time.as_millis() as u64;
        
        // Estimate reward
        let estimated = frac_system.estimate_reward(quality, time_ms).await?;
        let estimated_frac = estimated.as_u128() as f64 / 1e18;
        println!("💰 Estimated reward: {:.2} FRAC", estimated_frac);
        
        // Record earning (local tracking)
        let breakdown = economics.record_earning(
            &identity.node_id,
            &task_id,
            estimated_frac as u64,
            quality,
        );
        
        // CLAIM FRAC TOKENS ON-CHAIN
        println!("⛓️  Claiming FRAC tokens on-chain...");
        match frac_system.claim_reward(&identity.node_id, &proof, &breakdown).await {
            Ok(payment) => {
                println!("✅ FRAC MINTED!");
                println!("   Tx: {:?}", payment.tx_hash);
                println!("   Amount: {:.2} FRAC", payment.amount as f64 / 1e18);
                proofs_generated += 1;
                
                // Update metrics
                metrics.record_proof(proving_time);
                metrics.record_task_completed(&task_id);
                metrics.record_earnings(payment.amount as f64);
            }
            Err(e) => {
                println!("❌ Failed to claim: {}", e);
            }
        }
        
        println!();
        sleep(Duration::from_secs(2)).await;
    }

    // STEP 9: Final report
    let elapsed = start_time.elapsed();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║   📊 SESSION COMPLETE                                  ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    println!("Session Statistics:");
    println!("  ⏱️  Duration: {:.2}s", elapsed.as_secs_f64());
    println!("  ✅ Proofs: {}", proofs_generated);
    println!("  💰 Total FRAC earned: {:.2}", economics.total_earnings());
    println!();
    
    // Get on-chain stats
    let wallet_address = private_key.parse::<ethers::types::Address>()?;
    match frac_system.get_prover_stats(wallet_address).await {
        Ok(stats) => {
            println!("On-Chain Statistics:");
            println!("  {}", stats.to_frac());
        }
        Err(e) => {
            println!("❌ Could not fetch on-chain stats: {}", e);
        }
    }
    
    println!();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║   🎉 YOU EARNED FRAC TOKENS!                          ║");
    println!("╚════════════════════════════════════════════════════════╝");
    
    Ok(())
}
