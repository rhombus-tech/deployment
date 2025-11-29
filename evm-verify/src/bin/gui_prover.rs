// GUI Prover Backend - Tauri Integration
// Provides commands for the desktop app frontend

use evm_verify::fractal_network::{
    FracTokenomics, PermissionlessBootstrap, DecentralizedTaskPool,
    TaskSelectionStrategy, ProvingEconomics, CompletedProof,
    StatelessVMAdapter, FracRewardSystem,
};
use evm_verify::fractal_network::topology::ProverID;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use ethers::types::Address;

/// App state shared between Tauri commands
pub struct AppState {
    /// Is the prover currently running?
    pub is_running: Arc<RwLock<bool>>,
    
    /// User's wallet address
    pub wallet_address: Arc<RwLock<Option<Address>>>,
    
    /// Total FRAC earned
    pub total_earned: Arc<RwLock<u64>>,
    
    /// Proofs completed today
    pub proofs_today: Arc<RwLock<u32>>,
    
    /// Tokenomics system
    pub tokenomics: Arc<RwLock<FracTokenomics>>,
    
    /// Task pool
    pub task_pool: Arc<RwLock<DecentralizedTaskPool>>,
    
    /// Economics tracker
    pub economics: Arc<RwLock<ProvingEconomics>>,
    
    /// StatelessVM adapter
    pub stateless_adapter: Arc<RwLock<Option<StatelessVMAdapter>>>,
    
    /// Genesis NFT ID (if user has one)
    pub genesis_nft_id: Arc<RwLock<Option<u32>>>,
    
    /// Recent activity log
    pub activity_log: Arc<RwLock<Vec<ActivityEntry>>>,
}

impl AppState {
    pub fn new() -> Self {
        let genesis_block = 1000; // Will be set to actual genesis on mainnet
        
        Self {
            is_running: Arc::new(RwLock::new(false)),
            wallet_address: Arc::new(RwLock::new(None)),
            total_earned: Arc::new(RwLock::new(0)),
            proofs_today: Arc::new(RwLock::new(0)),
            tokenomics: Arc::new(RwLock::new(FracTokenomics::new(genesis_block))),
            task_pool: Arc::new(RwLock::new(DecentralizedTaskPool::new())),
            economics: Arc::new(RwLock::new(ProvingEconomics::new(1000))),
            stateless_adapter: Arc::new(RwLock::new(None)),
            genesis_nft_id: Arc::new(RwLock::new(None)),
            activity_log: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: u64,
    pub proof_type: String,
    pub task_id: String,
    pub reward: u64,
    pub block_number: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub is_running: bool,
    pub total_earned: u64,
    pub total_earned_usd: f64,
    pub today_earned: u64,
    pub week_earned: u64,
    pub total_proofs: u32,
    pub proofs_today: u32,
    pub proofs_per_minute: f64,
    pub genesis_nft_id: Option<u32>,
    pub staked_amount: u64,
    pub current_epoch: u64,
    pub epoch_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarningsData {
    pub hour: u64,
    pub earnings: u64,
}

// ==============================================================
// TAURI COMMANDS - Called from Frontend
// ==============================================================

/// Initialize the prover with user's wallet
// #[tauri::command] // Uncomment when using with Tauri
pub async fn initialize_prover(
    wallet_address: String,
    rpc_url: String,
    state: &AppState,
) -> Result<String, String> {
    println!("🔧 Initializing prover for wallet: {}", wallet_address);
    
    // Parse wallet address
    let address = wallet_address.parse::<Address>()
        .map_err(|e| format!("Invalid wallet address: {}", e))?;
    
    // Save wallet
    *state.wallet_address.write().await = Some(address);
    
    // Initialize StatelessVM adapter
    let adapter = StatelessVMAdapter::new_with_config(&rpc_url, true)
        .map_err(|e| format!("Failed to initialize VM: {}", e))?;
    
    *state.stateless_adapter.write().await = Some(adapter);
    
    // Check if user qualifies for genesis NFT
    let mut tokenomics = state.tokenomics.write().await;
    if let Ok(nft_id) = tokenomics.register_genesis_prover(address) {
        *state.genesis_nft_id.write().await = Some(nft_id);
        println!("🎉 Genesis NFT #{} minted!", nft_id);
    }
    
    Ok("Prover initialized successfully".to_string())
}

/// Start proving
// #[tauri::command]
pub async fn start_proving(state: &AppState) -> Result<(), String> {
    println!("▶️  Starting proving...");
    
    let mut is_running = state.is_running.write().await;
    *is_running = true;
    
    // Start proving loop in background
    let is_running_clone = state.is_running.clone();
    let wallet_address_clone = state.wallet_address.clone();
    let total_earned_clone = state.total_earned.clone();
    let proofs_today_clone = state.proofs_today.clone();
    let tokenomics_clone = state.tokenomics.clone();
    let task_pool_clone = state.task_pool.clone();
    let stateless_adapter_clone = state.stateless_adapter.clone();
    let activity_log_clone = state.activity_log.clone();
    
    tokio::spawn(async move {
        proving_loop_impl(
            is_running_clone,
            wallet_address_clone,
            total_earned_clone,
            proofs_today_clone,
            tokenomics_clone,
            task_pool_clone,
            stateless_adapter_clone,
            activity_log_clone,
        ).await;
    });
    
    Ok(())
}

/// Stop proving
// #[tauri::command]
pub async fn stop_proving(state: &AppState) -> Result<(), String> {
    println!("⏸  Stopping proving...");
    
    let mut is_running = state.is_running.write().await;
    *is_running = false;
    
    Ok(())
}

/// Get current dashboard stats
// #[tauri::command]
pub async fn get_stats(state: &AppState) -> Result<DashboardStats, String> {
    let is_running = *state.is_running.read().await;
    let total_earned = *state.total_earned.read().await;
    let proofs_today = *state.proofs_today.read().await;
    let genesis_nft_id = *state.genesis_nft_id.read().await;
    
    let tokenomics = state.tokenomics.read().await;
    let tokenomics_stats = tokenomics.get_stats();
    
    // Mock USD price (in production, fetch from oracle)
    let frac_price_usd = 0.20; // $0.20 per FRAC
    
    Ok(DashboardStats {
        is_running,
        total_earned,
        total_earned_usd: (total_earned as f64) * frac_price_usd,
        today_earned: total_earned / 7, // Mock: assume 1/7 earned today
        week_earned: total_earned,
        total_proofs: proofs_today * 100, // Mock
        proofs_today,
        proofs_per_minute: if is_running { 2.3 } else { 0.0 },
        genesis_nft_id,
        staked_amount: 10_000, // Mock
        current_epoch: tokenomics_stats.current_epoch,
        epoch_multiplier: tokenomics_stats.epoch_multiplier,
    })
}

/// Get recent activity
// #[tauri::command]
pub async fn get_activity(state: &AppState) -> Result<Vec<ActivityEntry>, String> {
    let activity = state.activity_log.read().await;
    Ok(activity.iter().rev().take(50).cloned().collect())
}

/// Get earnings chart data (last 24 hours)
// #[tauri::command]
pub async fn get_earnings_chart(state: &AppState) -> Result<Vec<EarningsData>, String> {
    // Mock data - in production, track hourly earnings
    let mut data = Vec::new();
    let base_hour = current_timestamp() / 3600;
    
    for i in 0..24 {
        data.push(EarningsData {
            hour: base_hour - (24 - i),
            earnings: 50 + (i * 10) % 100, // Mock: varies between 50-150
        });
    }
    
    Ok(data)
}

/// Update settings
// #[tauri::command]
pub async fn update_settings(
    enable_vulnerability_analysis: bool,
    auto_pause_gaming: bool,
    auto_pause_battery: bool,
    state: &AppState,
) -> Result<(), String> {
    println!("⚙️  Updating settings...");
    println!("   Vulnerability analysis: {}", enable_vulnerability_analysis);
    println!("   Auto-pause gaming: {}", auto_pause_gaming);
    println!("   Auto-pause battery: {}", auto_pause_battery);
    
    // Update StatelessVM adapter configuration
    if let Some(adapter) = state.stateless_adapter.write().await.as_mut() {
        // In production: adapter.set_vulnerability_analysis(enable_vulnerability_analysis);
    }
    
    Ok(())
}

// ==============================================================
// PROVING LOOP - Runs in Background
// ==============================================================

async fn proving_loop_impl(
    is_running: Arc<RwLock<bool>>,
    wallet_address: Arc<RwLock<Option<Address>>>,
    total_earned: Arc<RwLock<u64>>,
    proofs_today: Arc<RwLock<u32>>,
    tokenomics: Arc<RwLock<FracTokenomics>>,
    task_pool: Arc<RwLock<DecentralizedTaskPool>>,
    stateless_adapter: Arc<RwLock<Option<StatelessVMAdapter>>>,
    activity_log: Arc<RwLock<Vec<ActivityEntry>>>,
) {
    println!("🔄 Proving loop started");
    
    while *is_running.read().await {
        // Pull tasks from network
        let available_tasks = {
            let pool = task_pool.read().await;
            pool.select_tasks(TaskSelectionStrategy::PhiOptimized, 5)
        };
        
        if !available_tasks.is_empty() {
            for task_announcement in available_tasks {
                // Check if still running
                if !*is_running.read().await {
                    break;
                }
                
                // Claim task
                {
                    let pool = task_pool.read().await;
                    let _ = pool.claim_task(&task_announcement.task_id);
                }
                
                // Generate proof
                let proof_start = std::time::Instant::now();
                match generate_proof_simple(&task_announcement, &wallet_address, &tokenomics, &stateless_adapter).await {
                    Ok((proof, reward)) => {
                        let proving_time = proof_start.elapsed();
                        
                        // Update stats
                        {
                            let mut total = total_earned.write().await;
                            *total += reward;
                        }
                        {
                            let mut today = proofs_today.write().await;
                            *today += 1;
                        }
                        
                        // Add to activity log
                        {
                            let mut activity = activity_log.write().await;
                            activity.push(ActivityEntry {
                                timestamp: current_timestamp(),
                                proof_type: "Block Proof".to_string(),
                                task_id: task_announcement.task_id.clone(),
                                reward,
                                block_number: None,
                            });
                            
                            // Keep only last 100 entries
                            if activity.len() > 100 {
                                activity.remove(0);
                            }
                        }
                        
                        println!("✅ Proof completed in {:.2}ms: +{} FRAC", 
                            proving_time.as_millis(), reward);
                    }
                    Err(e) => {
                        eprintln!("❌ Proof failed: {}", e);
                    }
                }
            }
        }
        
        // Brief pause before next iteration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
    
    println!("🛑 Proving loop stopped");
}

async fn generate_proof_simple(
    task: &evm_verify::fractal_network::TaskAnnouncement,
    wallet_address: &Arc<RwLock<Option<Address>>>,
    tokenomics: &Arc<RwLock<FracTokenomics>>,
    stateless_adapter: &Arc<RwLock<Option<StatelessVMAdapter>>>,
) -> Result<(CompletedProof, u64), String> {
    // Try StatelessVM first
    if let Some(_adapter) = stateless_adapter.read().await.as_ref() {
        // In production: actually generate proof
        // let proof_data = adapter.prove_with_stateless_vm(&task.task).await?;
    }
    
    // Create mock proof for demo
    let proof = CompletedProof {
        task_id: task.task_id.clone(),
        aggregated_proof: vec![0u8; 128],
        phi_efficiency: 1.618,
        contributors: vec![ProverID("gui_prover".to_string())],
        completion_time: std::time::SystemTime::now(),
    };
    
    // Calculate reward
    let wallet = wallet_address.read().await;
    let reward = if let Some(addr) = *wallet {
        let tokenomics_guard = tokenomics.read().await;
        let calculation = tokenomics_guard.calculate_proof_reward(addr, &proof, 1000);
        calculation.total_reward
    } else {
        1000 // Base reward
    };
    
    Ok((proof, reward))
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ==============================================================
// MAIN - Entry Point for GUI Prover
// ==============================================================

#[tokio::main]
async fn main() {
    println!("💎 FRAC Prover GUI - Starting...");
    
    // For standalone testing without Tauri
    let state = Arc::new(AppState::new());
    
    // Initialize with test wallet
    let test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bB99";
    let test_rpc = "https://eth.llamarpc.com";
    
    match initialize_prover(
        test_wallet.to_string(),
        test_rpc.to_string(),
        &state,
    ).await {
        Ok(msg) => println!("✅ {}", msg),
        Err(e) => eprintln!("❌ Initialization failed: {}", e),
    }
    
    // Start proving
    if let Err(e) = start_proving(&state).await {
        eprintln!("❌ Failed to start: {}", e);
        return;
    }
    
    // Run for 30 seconds
    println!("Running for 30 seconds...");
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    
    // Get stats
    match get_stats(&state).await {
        Ok(stats) => {
            println!("\n📊 Final Stats:");
            println!("   Total earned: {} FRAC", stats.total_earned);
            println!("   Proofs today: {}", stats.proofs_today);
            println!("   Epoch: {} ({}x multiplier)", stats.current_epoch, stats.epoch_multiplier);
            if let Some(nft_id) = stats.genesis_nft_id {
                println!("   Genesis NFT: #{}", nft_id);
            }
        }
        Err(e) => eprintln!("❌ Failed to get stats: {}", e),
    }
    
    // Stop
    if let Err(e) = stop_proving(&state).await {
        eprintln!("❌ Failed to stop: {}", e);
    }
    
    println!("\n✅ GUI Prover test completed!");
}
