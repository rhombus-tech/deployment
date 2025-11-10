// Continuous Proving & Streaming Module
// World-class real-time proof generation and verification system

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, broadcast, Mutex};
use tokio::time::{Duration, Instant, sleep};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use futures::{SinkExt, StreamExt};

use crate::transaction::{Transaction, TransactionSequence};
use crate::types::{Address, StateRoot, VerificationLevel};
use crate::errors::VMError;
use crate::security::{SecurityVerifier, VerificationResult};
use crate::core::StatelessVM;

/// Configuration for continuous proving system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuousProvingConfig {
    /// Maximum transactions per proof batch
    pub max_batch_size: usize,
    /// Maximum time to wait before generating proof (ms)
    pub max_batch_time_ms: u64,
    /// Buffer size for incoming transactions
    pub tx_buffer_size: usize,
    /// Enable proof compression
    pub enable_compression: bool,
    /// Proof accumulation strategy
    pub accumulation_strategy: ProofAccumulationStrategy,
    /// Performance optimization level
    pub optimization_level: OptimizationLevel,
    /// Enable real-time metrics
    pub enable_metrics: bool,
}

impl Default for ContinuousProvingConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            max_batch_time_ms: 50,
            tx_buffer_size: 10000,
            enable_compression: true,
            accumulation_strategy: ProofAccumulationStrategy::Incremental,
            optimization_level: OptimizationLevel::Aggressive,
            enable_metrics: true,
        }
    }
}

/// Proof accumulation strategies for continuous proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofAccumulationStrategy {
    /// Generate incremental proofs that build on previous state
    Incremental,
    /// Generate complete proofs with full state verification
    Complete,
    /// Hybrid approach: incremental with periodic complete proofs
    Hybrid { complete_every: usize },
}

/// Performance optimization levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationLevel {
    /// Conservative optimizations, prioritize correctness
    Conservative,
    /// Balanced optimizations for production use
    Balanced,
    /// Aggressive optimizations for maximum throughput
    Aggressive,
}

/// Real-time transaction with streaming metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingTransaction {
    pub tx: Transaction,
    pub stream_id: String,
    pub sequence_number: u64,
    pub timestamp: u64,
    pub priority: TransactionPriority,
    pub dependencies: Vec<String>,
}

/// Transaction priority in the streaming pipeline
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Incremental proof with continuous accumulation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalProof {
    pub proof_id: String,
    pub sequence_number: u64,
    pub batch_start: u64,
    pub batch_end: u64,
    pub proof_data: Vec<u8>,
    pub state_root: StateRoot,
    pub previous_proof_id: Option<String>,
    pub verification_result: VerificationResult,
    pub compression_ratio: u64, // Changed from f64 to u64 for Eq trait compatibility
    pub generation_time_ms: u64,
}

/// Real-time metrics for continuous proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingMetrics {
    pub transactions_processed: u64,
    pub proofs_generated: u64,
    pub average_batch_size: f64,
    pub average_proof_time_ms: f64,
    pub throughput_tps: f64,
    pub current_queue_size: usize,
    pub error_rate: f64,
    pub compression_efficiency: f64,
    pub state_growth_rate: f64,
}

/// Events emitted by the streaming system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamingEvent {
    TransactionReceived { tx_id: String, stream_id: String },
    BatchFormed { batch_id: String, size: usize },
    ProofGenerated { proof: IncrementalProof },
    ProofVerified { proof_id: String, valid: bool },
    StateUpdated { new_root: StateRoot, sequence: u64 },
    Error { error: String, context: String },
    MetricsUpdate { metrics: StreamingMetrics },
}

/// Core continuous proving engine
pub struct ContinuousProvingEngine {
    config: ContinuousProvingConfig,
    vm: Arc<RwLock<StatelessVM>>,
    security_verifier: Arc<dyn SecurityVerifier>,
    
    // Streaming infrastructure
    tx_receiver: Arc<Mutex<mpsc::Receiver<StreamingTransaction>>>,
    tx_sender: mpsc::Sender<StreamingTransaction>,
    event_broadcaster: broadcast::Sender<StreamingEvent>,
    
    // Proof accumulation state
    current_batch: Arc<RwLock<Vec<StreamingTransaction>>>,
    proof_chain: Arc<RwLock<VecDeque<IncrementalProof>>>,
    current_sequence: Arc<RwLock<u64>>,
    
    // Performance tracking
    metrics: Arc<RwLock<StreamingMetrics>>,
    batch_timer: Arc<RwLock<Option<Instant>>>,
    
    // Active streams
    active_streams: Arc<RwLock<HashMap<String, StreamState>>>,
}

/// State tracking for individual transaction streams
#[derive(Debug, Clone)]
struct StreamState {
    stream_id: String,
    last_sequence: u64,
    transaction_count: u64,
    created_at: Instant,
    last_activity: Instant,
}

impl ContinuousProvingEngine {
    /// Create a new continuous proving engine
    pub fn new(
        config: ContinuousProvingConfig,
        vm: Arc<RwLock<StatelessVM>>,
        security_verifier: Arc<dyn SecurityVerifier>,
    ) -> Self {
        let (tx_sender, tx_receiver) = mpsc::channel(config.tx_buffer_size);
        let (event_broadcaster, _) = broadcast::channel(1000);
        
        Self {
            config,
            vm,
            security_verifier,
            tx_receiver: Arc::new(Mutex::new(tx_receiver)),
            tx_sender,
            event_broadcaster,
            current_batch: Arc::new(RwLock::new(Vec::new())),
            proof_chain: Arc::new(RwLock::new(VecDeque::new())),
            current_sequence: Arc::new(RwLock::new(0)),
            metrics: Arc::new(RwLock::new(StreamingMetrics::default())),
            batch_timer: Arc::new(RwLock::new(None)),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start the continuous proving engine
    pub async fn start(&self) -> Result<(), VMError> {
        // Start the main processing loop
        let engine = self.clone();
        tokio::spawn(async move {
            engine.processing_loop().await;
        });
        
        // Start batch timer
        let engine = self.clone();
        tokio::spawn(async move {
            engine.batch_timer_loop().await;
        });
        
        // Start metrics collection
        if self.config.enable_metrics {
            let engine = self.clone();
            tokio::spawn(async move {
                engine.metrics_loop().await;
            });
        }
        
        Ok(())
    }
    
    /// Submit a transaction to the continuous proving pipeline
    pub async fn submit_transaction(
        &self,
        tx: Transaction,
        stream_id: String,
        priority: TransactionPriority,
    ) -> Result<String, VMError> {
        let mut sequence = self.current_sequence.write().await;
        *sequence += 1;
        let sequence_number = *sequence;
        drop(sequence);
        
        let streaming_tx = StreamingTransaction {
            tx,
            stream_id: stream_id.clone(),
            sequence_number,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            priority,
            dependencies: Vec::new(),
        };
        
        let tx_id = format!("{}:{}", stream_id, sequence_number);
        
        // Update stream state
        {
            let mut streams = self.active_streams.write().await;
            let now = Instant::now();
            streams.entry(stream_id.clone()).and_modify(|s| {
                s.last_sequence = sequence_number;
                s.transaction_count += 1;
                s.last_activity = now;
            }).or_insert_with(|| StreamState {
                stream_id: stream_id.clone(),
                last_sequence: sequence_number,
                transaction_count: 1,
                created_at: now,
                last_activity: now,
            });
        }
        
        // Send to processing pipeline
        self.tx_sender.send(streaming_tx).await
            .map_err(|e| VMError::InvalidOperation { 
                description: format!("Failed to submit transaction: {}", e) 
            })?;
        
        // Emit event
        let _ = self.event_broadcaster.send(StreamingEvent::TransactionReceived { 
            tx_id: tx_id.clone(), 
            stream_id 
        });
        
        Ok(tx_id)
    }
    
    /// Subscribe to streaming events
    pub fn subscribe_events(&self) -> broadcast::Receiver<StreamingEvent> {
        self.event_broadcaster.subscribe()
    }
    
    /// Get current metrics
    pub async fn get_metrics(&self) -> StreamingMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Get current sequence number
    pub async fn get_current_sequence(&self) -> u64 {
        *self.current_sequence.read().await
    }
    
    /// Get proof chain (read-only access)
    pub async fn get_proof_chain(&self) -> Vec<IncrementalProof> {
        self.proof_chain.read().await.iter().cloned().collect()
    }
    
    /// Main transaction processing loop
    async fn processing_loop(&self) {
        let mut receiver = self.tx_receiver.lock().await;
        
        while let Some(streaming_tx) = receiver.recv().await {
            if let Err(e) = self.process_transaction(streaming_tx).await {
                let _ = self.event_broadcaster.send(StreamingEvent::Error { 
                    error: e.to_string(), 
                    context: "transaction_processing".to_string() 
                });
            }
        }
    }
    
    /// Process individual transaction and manage batching
    async fn process_transaction(&self, streaming_tx: StreamingTransaction) -> Result<(), VMError> {
        // Add to current batch
        let mut batch = self.current_batch.write().await;
        batch.push(streaming_tx);
        
        // Check if we should generate a proof
        let should_generate = batch.len() >= self.config.max_batch_size;
        
        if should_generate {
            let batch_txs = batch.drain(..).collect();
            drop(batch);
            
            self.generate_incremental_proof(batch_txs).await?;
        } else if batch.len() == 1 {
            // Start batch timer on first transaction
            *self.batch_timer.write().await = Some(Instant::now());
        }
        
        Ok(())
    }
    
    /// Timer-based batch processing
    async fn batch_timer_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        
        loop {
            interval.tick().await;
            
            let timer = self.batch_timer.read().await.clone();
            if let Some(start_time) = timer {
                if start_time.elapsed().as_millis() >= self.config.max_batch_time_ms as u128 {
                    drop(timer);
                    
                    // Generate proof for current batch if not empty
                    let mut batch = self.current_batch.write().await;
                    if !batch.is_empty() {
                        let batch_txs = batch.drain(..).collect();
                        drop(batch);
                        
                        if let Err(e) = self.generate_incremental_proof(batch_txs).await {
                            let _ = self.event_broadcaster.send(StreamingEvent::Error { 
                                error: e.to_string(), 
                                context: "batch_timer".to_string() 
                            });
                        }
                    }
                    
                    // Reset timer
                    *self.batch_timer.write().await = None;
                }
            }
        }
    }
    
    /// Generate incremental proof for transaction batch
    async fn generate_incremental_proof(&self, batch_txs: Vec<StreamingTransaction>) -> Result<(), VMError> {
        if batch_txs.is_empty() {
            return Ok(());
        }
        
        let proof_start = Instant::now();
        let batch_id = format!("batch_{}", chrono::Utc::now().timestamp_millis());
        
        // Emit batch formation event
        let _ = self.event_broadcaster.send(StreamingEvent::BatchFormed { 
            batch_id: batch_id.clone(), 
            size: batch_txs.len() 
        });
        
        // Convert to transaction sequence
        let transactions: Vec<Transaction> = batch_txs.iter().map(|stx| stx.tx.clone()).collect();
        let sequence = TransactionSequence::new(transactions, false);
        
        // Generate proof using the VM's security verifier
        let verification_level = VerificationLevel::Standard;
        let verification_result = self.security_verifier.verify_sequence(&sequence, verification_level).await?;
        
        // Execute the sequence to get new state root
        let mut vm = self.vm.write().await;
        let execution_results = vm.execute_sequence(sequence).await?;
        let new_state_root = vm.state_root().clone();
        drop(vm);
        
        // Get previous proof for chain linking
        let proof_chain = self.proof_chain.read().await;
        let previous_proof_id = proof_chain.back().map(|p| p.proof_id.clone());
        drop(proof_chain);
        
        // Create incremental proof
        let proof_data = self.serialize_proof_data(&execution_results, &verification_result).await?;
        let compressed_data = if self.config.enable_compression {
            self.compress_proof_data(&proof_data).await?
        } else {
            proof_data.clone()
        };
        
        let compression_ratio = if self.config.enable_compression {
            proof_data.len() as f64 / compressed_data.len() as f64
        } else {
            1.0
        };
        
        let batch_start = batch_txs.first().map(|tx| tx.sequence_number).unwrap_or(0);
        let batch_end = batch_txs.last().map(|tx| tx.sequence_number).unwrap_or(0);
        
        let incremental_proof = IncrementalProof {
            proof_id: uuid::Uuid::new_v4().to_string(),
            sequence_number: batch_end,
            batch_start,
            batch_end,
            proof_data: compressed_data,
            state_root: new_state_root.clone(),
            previous_proof_id,
            verification_result: verification_result.clone(),
            compression_ratio: compression_ratio as u64,
            generation_time_ms: proof_start.elapsed().as_millis() as u64,
        };
        
        // Add to proof chain
        {
            let mut proof_chain = self.proof_chain.write().await;
            proof_chain.push_back(incremental_proof.clone());
            
            // Maintain chain size based on strategy
            if proof_chain.len() > 1000 {
                proof_chain.pop_front();
            }
        }
        
        // Emit events
        let _ = self.event_broadcaster.send(StreamingEvent::ProofGenerated { 
            proof: incremental_proof.clone() 
        });
        let _ = self.event_broadcaster.send(StreamingEvent::ProofVerified { 
            proof_id: incremental_proof.proof_id.clone(), 
            valid: verification_result.is_valid() 
        });
        let _ = self.event_broadcaster.send(StreamingEvent::StateUpdated { 
            new_root: new_state_root, 
            sequence: batch_end 
        });
        
        // Update metrics
        self.update_metrics(batch_txs.len(), incremental_proof.generation_time_ms, compression_ratio).await;
        
        Ok(())
    }
    
    /// Serialize proof data for storage/transmission
    async fn serialize_proof_data(
        &self,
        execution_results: &[crate::transaction::TransactionStatus],
        verification_result: &VerificationResult,
    ) -> Result<Vec<u8>, VMError> {
        let proof_data = serde_json::json!({
            "execution_results": execution_results,
            "verification_result": verification_result,
            "timestamp": chrono::Utc::now().timestamp_millis()
        });
        
        serde_json::to_vec(&proof_data)
            .map_err(|e| VMError::Serialization(format!("Failed to serialize proof: {}", e)))
    }
    
    /// Compress proof data for efficiency
    async fn compress_proof_data(&self, data: &[u8]) -> Result<Vec<u8>, VMError> {
        // Use zstd for fast, high-ratio compression
        let compressed = zstd::bulk::compress(data, 3)
            .map_err(|e| VMError::InvalidOperation { 
                description: format!("Compression failed: {}", e) 
            })?;
        Ok(compressed)
    }
    
    /// Update streaming metrics
    async fn update_metrics(&self, batch_size: usize, proof_time_ms: u64, compression_ratio: f64) {
        let mut metrics = self.metrics.write().await;
        
        metrics.transactions_processed += batch_size as u64;
        metrics.proofs_generated += 1;
        
        // Update averages using exponential moving average
        let alpha = 0.1;
        metrics.average_batch_size = (1.0 - alpha) * metrics.average_batch_size + alpha * batch_size as f64;
        metrics.average_proof_time_ms = (1.0 - alpha) * metrics.average_proof_time_ms + alpha * proof_time_ms as f64;
        metrics.compression_efficiency = (1.0 - alpha) * metrics.compression_efficiency + alpha * compression_ratio;
        
        // Calculate throughput (transactions per second)
        if metrics.average_proof_time_ms > 0.0 {
            metrics.throughput_tps = (metrics.average_batch_size * 1000.0) / metrics.average_proof_time_ms;
        }
        
        metrics.current_queue_size = self.current_batch.read().await.len();
    }
    
    /// Metrics collection loop
    async fn metrics_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        
        loop {
            interval.tick().await;
            let metrics = self.get_metrics().await;
            let _ = self.event_broadcaster.send(StreamingEvent::MetricsUpdate { metrics });
        }
    }
}

impl Clone for ContinuousProvingEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            vm: self.vm.clone(),
            security_verifier: self.security_verifier.clone(),
            tx_receiver: self.tx_receiver.clone(),
            tx_sender: self.tx_sender.clone(),
            event_broadcaster: self.event_broadcaster.clone(),
            current_batch: self.current_batch.clone(),
            proof_chain: self.proof_chain.clone(),
            current_sequence: self.current_sequence.clone(),
            metrics: self.metrics.clone(),
            batch_timer: self.batch_timer.clone(),
            active_streams: self.active_streams.clone(),
        }
    }
}

impl Default for StreamingMetrics {
    fn default() -> Self {
        Self {
            transactions_processed: 0,
            proofs_generated: 0,
            average_batch_size: 0.0,
            average_proof_time_ms: 0.0,
            throughput_tps: 0.0,
            current_queue_size: 0,
            error_rate: 0.0,
            compression_efficiency: 1.0,
            state_growth_rate: 0.0,
        }
    }
}
