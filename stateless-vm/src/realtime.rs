use crate::prelude::*;
use crate::core::StatelessVM;
use crate::types::{BlockHeight, StateRoot};
use crate::errors::VMError;

use std::sync::Arc;
use std::collections::{HashMap, VecDeque, BinaryHeap};
use std::cmp::Ordering;
use tokio::sync::{RwLock, mpsc, broadcast, Mutex};
use tokio::time::{Duration, Instant, sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use url::Url;
use ethereum_types::{Address, H256, U256};

/// Block processing priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockPriority {
    /// Real-time blocks (0-5 minutes old) - highest priority
    RealTime = 1,
    /// Recent blocks (5-60 minutes old) - medium priority  
    Recent = 2,
    /// Historical blocks (>60 minutes old) - lowest priority
    Historical = 3,
}

impl PartialOrd for BlockPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

/// Block processing request with priority
#[derive(Debug, Clone)]
pub struct BlockProcessingRequest {
    pub block_number: u64,
    pub block_hash: H256,
    pub priority: BlockPriority,
    pub timestamp: Instant,
    pub retries: u32,
}

impl PartialEq for BlockProcessingRequest {
    fn eq(&self, other: &Self) -> bool {
        self.block_number == other.block_number
    }
}

impl Eq for BlockProcessingRequest {}

impl PartialOrd for BlockProcessingRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockProcessingRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority blocks come first (reverse order for BinaryHeap)
        other.priority.cmp(&self.priority)
            .then_with(|| other.block_number.cmp(&self.block_number))
    }
}

/// Real-time block data from Ethereum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumBlock {
    pub number: String,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub transactions: Vec<String>,
    pub state_root: String,
}

/// Block processing result
#[derive(Debug, Clone)]
pub struct BlockProcessingResult {
    pub block_number: u64,
    pub block_hash: H256,
    pub processing_time_ms: u64,
    pub transaction_count: usize,
    pub witness_size: usize,
    pub success: bool,
    pub error: Option<String>,
}

/// Real-time processing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealTimeStats {
    pub total_blocks_processed: u64,
    pub realtime_blocks_processed: u64,
    pub recent_blocks_processed: u64,
    pub historical_blocks_processed: u64,
    pub average_processing_time_ms: f64,
    pub blocks_per_second: f64,
    pub current_lag_seconds: u64,
    pub queue_size: usize,
    pub failed_blocks: u64,
}

/// Configuration for real-time processor
#[derive(Debug, Clone)]
pub struct RealTimeConfig {
    /// Ethereum WebSocket endpoint
    pub eth_ws_url: String,
    /// Maximum number of worker threads
    pub max_workers: usize,
    /// Real-time processing timeout (seconds)
    pub realtime_timeout_secs: u64,
    /// Maximum queue size before dropping historical blocks
    pub max_queue_size: usize,
    /// Target processing lag for real-time blocks (seconds)
    pub target_lag_secs: u64,
    /// Retry attempts for failed blocks
    pub max_retries: u32,
}

impl Default for RealTimeConfig {
    fn default() -> Self {
        Self {
            eth_ws_url: "wss://eth-mainnet.g.alchemy.com/v2/demo".to_string(),
            max_workers: 16,
            realtime_timeout_secs: 30,
            max_queue_size: 10000,
            target_lag_secs: 60, // Process blocks within 1 minute
            max_retries: 3,
        }
    }
}

/// Real-time zkEVM block processor
pub struct RealTimeProcessor {
    vm: Arc<RwLock<StatelessVM>>,
    config: RealTimeConfig,
    
    // Priority queue for block processing
    block_queue: Arc<Mutex<BinaryHeap<BlockProcessingRequest>>>,
    
    // Processing statistics
    stats: Arc<RwLock<RealTimeStats>>,
    
    // Communication channels
    block_sender: mpsc::UnboundedSender<BlockProcessingRequest>,
    result_sender: broadcast::Sender<BlockProcessingResult>,
    
    // Current Ethereum head
    current_head: Arc<RwLock<Option<u64>>>,
    
    // Processed blocks cache (to avoid duplicates)
    processed_blocks: Arc<RwLock<HashMap<u64, Instant>>>,
}

impl RealTimeProcessor {
    /// Create a new real-time processor
    pub fn new(vm: Arc<RwLock<StatelessVM>>, config: RealTimeConfig) -> Self {
        let (block_sender, _) = mpsc::unbounded_channel();
        let (result_sender, _) = broadcast::channel(1000);
        
        Self {
            vm,
            config,
            block_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            stats: Arc::new(RwLock::new(RealTimeStats::default())),
            block_sender,
            result_sender,
            current_head: Arc::new(RwLock::new(None)),
            processed_blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start the real-time processing system
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🚀 Starting real-time zkEVM processor...");
        
        // Start Ethereum WebSocket listener
        let ws_handle = self.start_ethereum_listener().await?;
        
        // Start worker pool
        let worker_handle = self.start_worker_pool().await?;
        
        // Start statistics updater
        let stats_handle = self.start_stats_updater().await?;
        
        // Start cleanup task
        let cleanup_handle = self.start_cleanup_task().await?;
        
        println!("✅ Real-time processor started with {} workers", self.config.max_workers);
        
        // Wait for all tasks to complete (they run indefinitely)
        tokio::try_join!(ws_handle, worker_handle, stats_handle, cleanup_handle)?;
        
        Ok(())
    }
    
    /// Start Ethereum WebSocket listener for new blocks
    async fn start_ethereum_listener(&self) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let url = Url::parse(&self.config.eth_ws_url)?;
        let block_sender = self.block_sender.clone();
        let current_head = self.current_head.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                match Self::connect_and_listen(&url, &block_sender, &current_head).await {
                    Ok(_) => {
                        println!("✅ Ethereum WebSocket connection closed normally");
                    }
                    Err(e) => {
                        println!("❌ Ethereum WebSocket error: {}", e);
                        println!("🔄 Reconnecting in 5 seconds...");
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Connect to Ethereum WebSocket and listen for new blocks
    async fn connect_and_listen(
        url: &Url,
        block_sender: &mpsc::UnboundedSender<BlockProcessingRequest>,
        current_head: &Arc<RwLock<Option<u64>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (ws_stream, _) = connect_async(url).await?;
        let (mut write, mut read) = ws_stream.split();
        
        // Subscribe to new heads
        let subscribe_msg = serde_json::json!({
            "id": 1,
            "method": "eth_subscribe",
            "params": ["newHeads"]
        });
        
        write.send(Message::Text(subscribe_msg.to_string())).await?;
        println!("📡 Subscribed to Ethereum newHeads");
        
        while let Some(msg) = read.next().await {
            match msg? {
                Message::Text(text) => {
                    if let Ok(data) = serde_json::from_str::<Value>(&text) {
                        if let Some(params) = data.get("params") {
                            if let Some(result) = params.get("result") {
                                if let Some(block_number_hex) = result.get("number").and_then(|n| n.as_str()) {
                                    if let Ok(block_number) = u64::from_str_radix(&block_number_hex[2..], 16) {
                                        let block_hash = result.get("hash")
                                            .and_then(|h| h.as_str())
                                            .and_then(|h| h.parse::<H256>().ok())
                                            .unwrap_or_default();
                                        
                                        // Update current head
                                        *current_head.write().await = Some(block_number);
                                        
                                        // Queue block for real-time processing
                                        let request = BlockProcessingRequest {
                                            block_number,
                                            block_hash,
                                            priority: BlockPriority::RealTime,
                                            timestamp: Instant::now(),
                                            retries: 0,
                                        };
                                        
                                        if let Err(e) = block_sender.send(request) {
                                            println!("❌ Failed to queue real-time block {}: {}", block_number, e);
                                        } else {
                                            println!("📦 Queued real-time block #{}", block_number);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Message::Close(_) => {
                    println!("🔌 WebSocket connection closed");
                    break;
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Start the worker pool for processing blocks
    async fn start_worker_pool(&self) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let mut block_receiver = self.block_sender.subscribe();
        let block_queue = self.block_queue.clone();
        let vm = self.vm.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let result_sender = self.result_sender.clone();
        let processed_blocks = self.processed_blocks.clone();
        let current_head = self.current_head.clone();
        
        let handle = tokio::spawn(async move {
            // Start queue processor
            let queue_processor = {
                let block_queue = block_queue.clone();
                let vm = vm.clone();
                let config = config.clone();
                let stats = stats.clone();
                let result_sender = result_sender.clone();
                let processed_blocks = processed_blocks.clone();
                let current_head = current_head.clone();
                
                tokio::spawn(async move {
                    loop {
                        // Get highest priority block from queue
                        let block_request = {
                            let mut queue = block_queue.lock().await;
                            queue.pop()
                        };
                        
                        if let Some(request) = block_request {
                            // Check if already processed recently
                            let should_process = {
                                let processed = processed_blocks.read().await;
                                !processed.contains_key(&request.block_number) ||
                                processed.get(&request.block_number)
                                    .map(|t| t.elapsed() > Duration::from_secs(3600))
                                    .unwrap_or(true)
                            };
                            
                            if should_process {
                                Self::process_block(
                                    &vm,
                                    &config,
                                    &stats,
                                    &result_sender,
                                    &processed_blocks,
                                    &current_head,
                                    request,
                                ).await;
                            }
                        } else {
                            // No blocks in queue, sleep briefly
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                })
            };
            
            // Start block receiver
            let block_receiver_task = tokio::spawn(async move {
                while let Ok(request) = block_receiver.recv().await {
                    let mut queue = block_queue.lock().await;
                    
                    // Manage queue size
                    if queue.len() >= config.max_queue_size {
                        // Remove lowest priority items
                        let mut temp_queue = Vec::new();
                        while let Some(item) = queue.pop() {
                            if item.priority != BlockPriority::Historical || temp_queue.len() < config.max_queue_size / 2 {
                                temp_queue.push(item);
                            }
                        }
                        queue.clear();
                        for item in temp_queue {
                            queue.push(item);
                        }
                    }
                    
                    queue.push(request);
                }
            });
            
            // Wait for both tasks
            tokio::try_join!(queue_processor, block_receiver_task).unwrap();
        });
        
        Ok(handle)
    }
    
    /// Process a single block
    async fn process_block(
        vm: &Arc<RwLock<StatelessVM>>,
        config: &RealTimeConfig,
        stats: &Arc<RwLock<RealTimeStats>>,
        result_sender: &broadcast::Sender<BlockProcessingResult>,
        processed_blocks: &Arc<RwLock<HashMap<u64, Instant>>>,
        current_head: &Arc<RwLock<Option<u64>>>,
        request: BlockProcessingRequest,
    ) {
        let start_time = Instant::now();
        let block_number = request.block_number;
        
        println!("⚡ Processing block #{} (priority: {:?})", block_number, request.priority);
        
        // Determine timeout based on priority
        let timeout_duration = Duration::from_secs(match request.priority {
            BlockPriority::RealTime => config.realtime_timeout_secs,
            BlockPriority::Recent => config.realtime_timeout_secs * 2,
            BlockPriority::Historical => config.realtime_timeout_secs * 4,
        });
        
        let result = match timeout(timeout_duration, Self::execute_block_processing(vm, block_number)).await {
            Ok(Ok((transaction_count, witness_size))) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                
                // Mark as processed
                {
                    let mut processed = processed_blocks.write().await;
                    processed.insert(block_number, Instant::now());
                }
                
                // Update statistics
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_blocks_processed += 1;
                    
                    match request.priority {
                        BlockPriority::RealTime => stats_guard.realtime_blocks_processed += 1,
                        BlockPriority::Recent => stats_guard.recent_blocks_processed += 1,
                        BlockPriority::Historical => stats_guard.historical_blocks_processed += 1,
                    }
                    
                    // Update average processing time
                    let total = stats_guard.total_blocks_processed as f64;
                    stats_guard.average_processing_time_ms = 
                        (stats_guard.average_processing_time_ms * (total - 1.0) + processing_time as f64) / total;
                        
                    // Update current lag
                    if let Some(head) = *current_head.read().await {
                        stats_guard.current_lag_seconds = (head.saturating_sub(block_number)) * 12; // 12 seconds per block
                    }
                }
                
                println!("✅ Block #{} processed in {}ms ({} tx, {} bytes)", 
                    block_number, processing_time, transaction_count, witness_size);
                
                BlockProcessingResult {
                    block_number,
                    block_hash: request.block_hash,
                    processing_time_ms: processing_time,
                    transaction_count,
                    witness_size,
                    success: true,
                    error: None,
                }
            }
            Ok(Err(e)) => {
                println!("❌ Block #{} processing failed: {}", block_number, e);
                
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.failed_blocks += 1;
                }
                
                BlockProcessingResult {
                    block_number,
                    block_hash: request.block_hash,
                    processing_time_ms: start_time.elapsed().as_millis() as u64,
                    transaction_count: 0,
                    witness_size: 0,
                    success: false,
                    error: Some(e.to_string()),
                }
            }
            Err(_) => {
                println!("⏱️ Block #{} processing timed out after {:?}", block_number, timeout_duration);
                
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.failed_blocks += 1;
                }
                
                BlockProcessingResult {
                    block_number,
                    block_hash: request.block_hash,
                    processing_time_ms: timeout_duration.as_millis() as u64,
                    transaction_count: 0,
                    witness_size: 0,
                    success: false,
                    error: Some("Processing timeout".to_string()),
                }
            }
        };
        
        // Send result
        let _ = result_sender.send(result);
    }
    
    /// Execute block processing with the VM
    async fn execute_block_processing(
        vm: &Arc<RwLock<StatelessVM>>,
        block_number: u64,
    ) -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
        // This is where you'd integrate with your actual zkEVM processing
        // For now, simulate processing
        
        // Get block data from Ethereum
        let block_data = Self::fetch_block_data(block_number).await?;
        
        // Process with zkEVM
        let vm_guard = vm.read().await;
        
        // Simulate witness generation
        let transaction_count = block_data.transactions.len();
        let witness_size = transaction_count * 1024; // Estimate
        
        // Simulate your 72-156ms proving time
        let processing_delay = Duration::from_millis(72 + (rand::random::<u64>() % 84));
        sleep(processing_delay).await;
        
        Ok((transaction_count, witness_size))
    }
    
    /// Fetch block data from Ethereum
    async fn fetch_block_data(block_number: u64) -> Result<EthereumBlock, Box<dyn std::error::Error + Send + Sync>> {
        // Simulate fetching block data
        // In real implementation, this would call eth_getBlockByNumber
        
        Ok(EthereumBlock {
            number: format!("0x{:x}", block_number),
            hash: format!("0x{:064x}", block_number), // Fake hash
            parent_hash: format!("0x{:064x}", block_number - 1),
            timestamp: format!("0x{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
            gas_limit: "0x1c9c380".to_string(),
            gas_used: "0x1c9c380".to_string(),
            transactions: vec![format!("0x{:064x}", block_number); 200], // Simulate 200 transactions
            state_root: format!("0x{:064x}", block_number),
        })
    }
    
    /// Start statistics updater
    async fn start_stats_updater(&self) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let stats = self.stats.clone();
        let block_queue = self.block_queue.clone();
        
        let handle = tokio::spawn(async move {
            let mut last_processed = 0u64;
            
            loop {
                sleep(Duration::from_secs(10)).await;
                
                let (current_processed, queue_size) = {
                    let stats_guard = stats.read().await;
                    let queue_guard = block_queue.lock().await;
                    (stats_guard.total_blocks_processed, queue_guard.len())
                };
                
                // Calculate blocks per second
                let blocks_per_second = (current_processed - last_processed) as f64 / 10.0;
                last_processed = current_processed;
                
                // Update stats
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.blocks_per_second = blocks_per_second;
                    stats_guard.queue_size = queue_size;
                }
                
                // Print status
                let stats_guard = stats.read().await;
                println!("📊 Stats: {} blocks processed, {:.2} blocks/s, {} in queue, {:.1}ms avg, {} sec lag", 
                    stats_guard.total_blocks_processed,
                    stats_guard.blocks_per_second,
                    stats_guard.queue_size,
                    stats_guard.average_processing_time_ms,
                    stats_guard.current_lag_seconds
                );
            }
        });
        
        Ok(handle)
    }
    
    /// Start cleanup task for old processed blocks
    async fn start_cleanup_task(&self) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let processed_blocks = self.processed_blocks.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(3600)).await; // Run every hour
                
                let mut processed = processed_blocks.write().await;
                let cutoff = Instant::now() - Duration::from_secs(86400); // 24 hours
                
                processed.retain(|_, timestamp| *timestamp > cutoff);
                
                println!("🧹 Cleaned up old processed blocks cache");
            }
        });
        
        Ok(handle)
    }
    
    /// Add a historical block for processing
    pub async fn add_historical_block(&self, block_number: u64, block_hash: H256) {
        let request = BlockProcessingRequest {
            block_number,
            block_hash,
            priority: BlockPriority::Historical,
            timestamp: Instant::now(),
            retries: 0,
        };
        
        let _ = self.block_sender.send(request);
    }
    
    /// Get current processing statistics
    pub async fn get_stats(&self) -> RealTimeStats {
        self.stats.read().await.clone()
    }
    
    /// Subscribe to processing results
    pub fn subscribe_results(&self) -> broadcast::Receiver<BlockProcessingResult> {
        self.result_sender.subscribe()
    }
}

/// API endpoint for real-time processing status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeStatusResponse {
    pub stats: RealTimeStats,
    pub is_realtime: bool,
    pub current_head: Option<u64>,
    pub processing_lag_seconds: u64,
    pub queue_breakdown: HashMap<String, usize>,
}
