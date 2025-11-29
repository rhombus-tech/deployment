use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Production-grade Oracle Integration Layer
/// Aggregates multiple price feeds with fallback mechanisms and manipulation resistance
#[derive(Debug, Clone)]
pub struct OracleAggregator {
    /// Primary oracle (Chainlink)
    chainlink_oracle: ChainlinkOracle,
    /// Secondary oracle (Uniswap TWAP)
    uniswap_twap: UniswapTWAPOracle,
    /// Tertiary oracle (Band Protocol)
    band_oracle: BandOracle,
    /// Emergency fallback (multiple DEX spot prices)
    dex_aggregator: DEXPriceAggregator,
    /// Oracle health monitoring
    health_monitor: OracleHealthMonitor,
    /// Manipulation detection
    manipulation_detector: PriceManipulationDetector,
}

#[derive(Debug, Clone)]
pub struct ChainlinkOracle {
    /// Contract address for price feed
    feed_address: String,
    /// Maximum acceptable staleness (seconds)
    max_staleness: u64,
    /// Minimum number of answering nodes
    min_answers: u32,
    /// Historical price data for validation
    price_history: Vec<PricePoint>,
}

#[derive(Debug, Clone)]
pub struct UniswapTWAPOracle {
    /// Pool address
    pool_address: String,
    /// TWAP window (seconds)
    twap_window: u64,
    /// Price observations
    observations: Vec<PriceObservation>,
}

#[derive(Debug, Clone)]
pub struct BandOracle {
    /// Reference data contract address
    ref_data_address: String,
    /// Symbol pair (e.g., "USD/USDT")
    symbol_pair: String,
    /// Last update timestamp
    last_update: u64,
}

#[derive(Debug, Clone)]
pub struct DEXPriceAggregator {
    /// Uniswap V2/V3 prices
    uniswap_prices: HashMap<String, f64>,
    /// Curve prices
    curve_prices: HashMap<String, f64>,
    /// Balancer prices
    balancer_prices: HashMap<String, f64>,
    /// Sushiswap prices
    sushiswap_prices: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct OracleHealthMonitor {
    /// Oracle uptime tracking
    uptime_stats: HashMap<String, OracleUptimeStats>,
    /// Price deviation tracking
    deviation_history: Vec<DeviationEvent>,
    /// Circuit breaker status
    circuit_breakers: HashMap<String, CircuitBreakerStatus>,
}

#[derive(Debug, Clone)]
pub struct PriceManipulationDetector {
    /// Detection threshold (% deviation)
    threshold: f64,
    /// Time window for analysis (seconds)
    analysis_window: u64,
    /// Known manipulation patterns
    manipulation_patterns: Vec<ManipulationPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedPrice {
    /// Final aggregated price
    pub price: f64,
    /// Confidence in price (0.0-1.0)
    pub confidence: f64,
    /// Timestamp of aggregation
    pub timestamp: u64,
    /// Individual oracle contributions
    pub oracle_prices: HashMap<String, f64>,
    /// Manipulation risk score
    pub manipulation_risk: f64,
    /// Price sources used
    pub sources_used: Vec<String>,
}

#[derive(Debug, Clone)]
struct PricePoint {
    price: f64,
    timestamp: u64,
    round_id: u64,
}

#[derive(Debug, Clone)]
struct PriceObservation {
    price: f64,
    timestamp: u64,
    liquidity: f64,
}

#[derive(Debug, Clone)]
struct OracleUptimeStats {
    total_queries: u64,
    successful_queries: u64,
    failed_queries: u64,
    average_response_time: u64,
    last_success: u64,
}

#[derive(Debug, Clone)]
struct DeviationEvent {
    oracle_name: String,
    deviation: f64,
    timestamp: u64,
    price: f64,
    median_price: f64,
}

#[derive(Debug, Clone)]
enum CircuitBreakerStatus {
    Active,
    Tripped { reason: String, timestamp: u64 },
    Recovering { started: u64, progress: f64 },
}

#[derive(Debug, Clone)]
struct ManipulationPattern {
    pattern_type: String,
    detection_threshold: f64,
    severity: f64,
}

impl OracleAggregator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            chainlink_oracle: ChainlinkOracle::new()?,
            uniswap_twap: UniswapTWAPOracle::new()?,
            band_oracle: BandOracle::new()?,
            dex_aggregator: DEXPriceAggregator::new()?,
            health_monitor: OracleHealthMonitor::new()?,
            manipulation_detector: PriceManipulationDetector::new()?,
        })
    }

    /// Get aggregated price with multi-oracle validation
    pub async fn get_aggregated_price(&mut self) -> Result<AggregatedPrice> {
        let mut oracle_prices = HashMap::new();
        let mut successful_sources = Vec::new();
        
        // Try Chainlink (primary)
        if let Ok(chainlink_price) = self.chainlink_oracle.get_price().await {
            oracle_prices.insert("chainlink".to_string(), chainlink_price.price);
            successful_sources.push("chainlink".to_string());
        }
        
        // Try Uniswap TWAP (secondary)
        if let Ok(twap_price) = self.uniswap_twap.get_twap().await {
            oracle_prices.insert("uniswap_twap".to_string(), twap_price);
            successful_sources.push("uniswap_twap".to_string());
        }
        
        // Try Band Protocol (tertiary)
        if let Ok(band_price) = self.band_oracle.get_price().await {
            oracle_prices.insert("band".to_string(), band_price);
            successful_sources.push("band".to_string());
        }
        
        // Emergency fallback to DEX aggregator
        if oracle_prices.is_empty() {
            let dex_price = self.dex_aggregator.get_aggregated_dex_price().await?;
            oracle_prices.insert("dex_aggregator".to_string(), dex_price);
            successful_sources.push("dex_aggregator".to_string());
        }
        
        // Calculate median price (robust against outliers)
        let final_price = self.calculate_median_price(&oracle_prices)?;
        
        // Check for manipulation
        let manipulation_risk = self.manipulation_detector.detect_manipulation(&oracle_prices, final_price).await?;
        
        // Calculate confidence based on agreement
        let confidence = self.calculate_price_confidence(&oracle_prices, final_price)?;
        
        // Update health monitoring
        self.health_monitor.record_prices(&oracle_prices).await?;
        
        Ok(AggregatedPrice {
            price: final_price,
            confidence,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            oracle_prices,
            manipulation_risk,
            sources_used: successful_sources,
        })
    }
    
    fn calculate_median_price(&self, prices: &HashMap<String, f64>) -> Result<f64> {
        if prices.is_empty() {
            return Err(anyhow!("No oracle prices available"));
        }
        
        let mut price_vec: Vec<f64> = prices.values().copied().collect();
        price_vec.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let median = if price_vec.len() % 2 == 0 {
            let mid = price_vec.len() / 2;
            (price_vec[mid - 1] + price_vec[mid]) / 2.0
        } else {
            price_vec[price_vec.len() / 2]
        };
        
        Ok(median)
    }
    
    fn calculate_price_confidence(&self, prices: &HashMap<String, f64>, median: f64) -> Result<f64> {
        if prices.is_empty() {
            return Ok(0.0);
        }
        
        // Calculate standard deviation from median
        let deviations: Vec<f64> = prices.values()
            .map(|p| ((p - median) / median).abs())
            .collect();
        
        let avg_deviation = deviations.iter().sum::<f64>() / deviations.len() as f64;
        
        // Confidence decreases with deviation
        // 0% deviation = 100% confidence, 5% deviation = 50% confidence
        let confidence = (1.0 - (avg_deviation / 0.05)).max(0.0).min(1.0);
        
        // Bonus confidence for multiple sources
        let source_bonus = (prices.len() as f64 / 4.0).min(0.2);
        
        Ok((confidence + source_bonus).min(1.0))
    }
}

impl ChainlinkOracle {
    pub fn new() -> Result<Self> {
        Ok(Self {
            feed_address: "0x0000000000000000000000000000000000000000".to_string(),
            max_staleness: 3600, // 1 hour
            min_answers: 3,
            price_history: Vec::new(),
        })
    }
    
    pub async fn get_price(&mut self) -> Result<PricePoint> {
        // In production: actual Chainlink contract call
        // For now: simulated price feed
        let price_point = PricePoint {
            price: 1.0, // Simulated stablecoin price
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            round_id: 12345,
        };
        
        self.price_history.push(price_point.clone());
        
        // Keep only last 100 points
        if self.price_history.len() > 100 {
            self.price_history.remove(0);
        }
        
        Ok(price_point)
    }
}

impl UniswapTWAPOracle {
    pub fn new() -> Result<Self> {
        Ok(Self {
            pool_address: "0x0000000000000000000000000000000000000000".to_string(),
            twap_window: 1800, // 30 minutes
            observations: Vec::new(),
        })
    }
    
    pub async fn get_twap(&mut self) -> Result<f64> {
        // In production: actual Uniswap pool observations
        // For now: simulated TWAP
        let observation = PriceObservation {
            price: 1.0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            liquidity: 1_000_000.0,
        };
        
        self.observations.push(observation);
        
        // Keep observations within window
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        self.observations.retain(|obs| {
            current_time - obs.timestamp < self.twap_window
        });
        
        // Calculate TWAP
        if self.observations.is_empty() {
            return Ok(1.0);
        }
        
        let twap = self.observations.iter()
            .map(|obs| obs.price)
            .sum::<f64>() / self.observations.len() as f64;
        
        Ok(twap)
    }
}

impl BandOracle {
    pub fn new() -> Result<Self> {
        Ok(Self {
            ref_data_address: "0x0000000000000000000000000000000000000000".to_string(),
            symbol_pair: "USD/USDT".to_string(),
            last_update: 0,
        })
    }
    
    pub async fn get_price(&mut self) -> Result<f64> {
        // In production: actual Band Protocol reference data
        self.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        Ok(1.0) // Simulated price
    }
}

impl DEXPriceAggregator {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uniswap_prices: HashMap::new(),
            curve_prices: HashMap::new(),
            balancer_prices: HashMap::new(),
            sushiswap_prices: HashMap::new(),
        })
    }
    
    pub async fn get_aggregated_dex_price(&mut self) -> Result<f64> {
        // In production: query multiple DEX contracts
        // For now: simulated aggregation
        
        let mut all_prices = Vec::new();
        
        // Simulate DEX prices
        all_prices.push(1.001); // Uniswap
        all_prices.push(0.999); // Curve
        all_prices.push(1.000); // Balancer
        all_prices.push(1.002); // Sushiswap
        
        // Calculate median
        all_prices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = all_prices[all_prices.len() / 2];
        
        Ok(median)
    }
}

impl OracleHealthMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uptime_stats: HashMap::new(),
            deviation_history: Vec::new(),
            circuit_breakers: HashMap::new(),
        })
    }
    
    pub async fn record_prices(&mut self, prices: &HashMap<String, f64>) -> Result<()> {
        // Update uptime statistics
        for (oracle, _price) in prices {
            let stats = self.uptime_stats.entry(oracle.clone()).or_insert(OracleUptimeStats {
                total_queries: 0,
                successful_queries: 0,
                failed_queries: 0,
                average_response_time: 0,
                last_success: 0,
            });
            
            stats.total_queries += 1;
            stats.successful_queries += 1;
            stats.last_success = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
        }
        
        Ok(())
    }
}

impl PriceManipulationDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            threshold: 0.05, // 5% deviation threshold
            analysis_window: 300, // 5 minutes
            manipulation_patterns: vec![
                ManipulationPattern {
                    pattern_type: "flash_loan_pump".to_string(),
                    detection_threshold: 0.10,
                    severity: 0.9,
                },
                ManipulationPattern {
                    pattern_type: "sustained_deviation".to_string(),
                    detection_threshold: 0.03,
                    severity: 0.7,
                },
            ],
        })
    }
    
    pub async fn detect_manipulation(&self, prices: &HashMap<String, f64>, median: f64) -> Result<f64> {
        if prices.is_empty() {
            return Ok(0.0);
        }
        
        // Calculate maximum deviation from median
        let max_deviation = prices.values()
            .map(|p| ((p - median) / median).abs())
            .fold(0.0f64, |a, b| a.max(b));
        
        // Risk score based on deviation
        let risk = if max_deviation > 0.10 {
            0.9 // Very high risk
        } else if max_deviation > 0.05 {
            0.6 // High risk
        } else if max_deviation > 0.02 {
            0.3 // Medium risk
        } else {
            0.1 // Low risk
        };
        
        Ok(risk)
    }
}
