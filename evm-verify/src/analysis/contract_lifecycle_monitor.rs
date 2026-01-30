/// Contract Lifecycle Monitor (Phase 2: Continuous Monitoring)
///
/// Automatically detects when contracts need reverification:
/// - Bytecode changes (upgrades)
/// - TVL threshold breaches
/// - Time-based expiration
/// - Dependency changes (oracles, bridges)
/// - New vulnerability classes discovered

use serde::{Serialize, Deserialize};
use ethers::{
    providers::{Provider, Http, Middleware},
    types::{Address, H256, U256, BlockNumber},
    core::types::Bytes,
};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use std::collections::HashMap;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

use super::security_proof_generator::{
    SecurityCertificate,
    ReverificationConfig,
};

/// Main contract lifecycle monitor
pub struct ContractLifecycleMonitor {
    provider: Arc<Provider<Http>>,
    monitored_contracts: Arc<tokio::sync::RwLock<HashMap<Address, MonitoredContract>>>,
    check_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredContract {
    pub address: Address,
    pub latest_certificate: SecurityCertificate,
    pub monitoring_config: ReverificationConfig,
    pub original_bytecode_hash: [u8; 32],
    pub is_proxy: bool,
    pub implementation_address: Option<Address>,
    pub monitored_dependencies: Vec<Address>,
    pub last_tvl_check: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReverificationTrigger {
    BytecodeChanged {
        old_hash: [u8; 32],
        new_hash: [u8; 32],
    },
    ProxyUpgraded {
        old_implementation: Address,
        new_implementation: Address,
    },
    TvlThresholdExceeded {
        threshold: U256,
        current_tvl: U256,
    },
    TimeExpired {
        expires_at: u64,
        current_time: u64,
    },
    DependencyChanged {
        dependency: Address,
        change_type: String,
    },
    NewDetectorAdded {
        detector_name: String,
        detector_version: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverificationAlert {
    pub contract_address: Address,
    pub trigger: ReverificationTrigger,
    pub severity: AlertSeverity,
    pub timestamp: u64,
    pub action_required: String,
    pub webhook_sent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Critical, // Immediate action required
    High,     // Action required within 24h
    Medium,   // Action required within 7 days
    Low,      // Informational
}

impl ContractLifecycleMonitor {
    pub fn new(rpc_url: &str, check_interval_seconds: u64) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)
            .context("Failed to create Ethereum provider")?;
        
        Ok(Self {
            provider: Arc::new(provider),
            monitored_contracts: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            check_interval_seconds,
        })
    }
    
    /// Add a contract to continuous monitoring
    pub async fn monitor_contract(
        &self,
        address: Address,
        certificate: SecurityCertificate,
    ) -> Result<()> {
        info!("Adding contract {:?} to lifecycle monitoring", address);
        
        // Check if it's a proxy
        let (is_proxy, implementation) = self.detect_proxy_pattern(address).await?;
        
        // Extract monitored dependencies (oracles, bridges, etc.)
        let dependencies = self.extract_dependencies(address).await?;
        
        let monitored = MonitoredContract {
            address,
            latest_certificate: certificate.clone(),
            monitoring_config: certificate.reverification_triggers.clone(),
            original_bytecode_hash: certificate.bytecode_hash,
            is_proxy,
            implementation_address: implementation,
            monitored_dependencies: dependencies,
            last_tvl_check: None,
        };
        
        let mut contracts = self.monitored_contracts.write().await;
        contracts.insert(address, monitored);
        
        info!("Contract {:?} now monitored (proxy: {})", address, is_proxy);
        Ok(())
    }
    
    /// Start the monitoring loop
    pub async fn start_monitoring(self: Arc<Self>) -> Result<()> {
        info!("Starting contract lifecycle monitor (interval: {}s)", self.check_interval_seconds);
        
        let mut interval = interval(Duration::from_secs(self.check_interval_seconds));
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.check_all_contracts().await {
                error!("Error during monitoring check: {}", e);
            }
        }
    }
    
    /// Check all monitored contracts for reverification triggers
    async fn check_all_contracts(&self) -> Result<()> {
        let contracts = self.monitored_contracts.read().await;
        let addresses: Vec<Address> = contracts.keys().copied().collect();
        drop(contracts); // Release lock
        
        for address in addresses {
            if let Err(e) = self.check_contract(address).await {
                error!("Error checking contract {:?}: {}", address, e);
            }
        }
        
        Ok(())
    }
    
    /// Check a single contract for reverification triggers
    async fn check_contract(&self, address: Address) -> Result<()> {
        let contracts = self.monitored_contracts.read().await;
        let monitored = contracts.get(&address)
            .context("Contract not found in monitoring list")?
            .clone();
        drop(contracts);
        
        let mut alerts = Vec::new();
        
        // 1. Check bytecode changes
        if monitored.monitoring_config.on_bytecode_change {
            if let Some(alert) = self.check_bytecode_change(&monitored).await? {
                alerts.push(alert);
            }
        }
        
        // 2. Check proxy upgrades
        if monitored.monitoring_config.on_upgrade_detected && monitored.is_proxy {
            if let Some(alert) = self.check_proxy_upgrade(&monitored).await? {
                alerts.push(alert);
            }
        }
        
        // 3. Check TVL threshold
        if let Some(threshold) = monitored.monitoring_config.tvl_threshold_wei {
            if let Some(alert) = self.check_tvl_threshold(&monitored, threshold).await? {
                alerts.push(alert);
            }
        }
        
        // 4. Check time-based expiration
        if let Some(alert) = self.check_time_expiration(&monitored).await? {
            alerts.push(alert);
        }
        
        // 5. Check dependency changes
        if monitored.monitoring_config.on_dependency_change {
            if let Some(alert) = self.check_dependency_changes(&monitored).await? {
                alerts.push(alert);
            }
        }
        
        // Send alerts
        for alert in alerts {
            self.send_alert(&monitored, alert).await?;
        }
        
        Ok(())
    }
    
    /// Check if bytecode has changed
    async fn check_bytecode_change(&self, monitored: &MonitoredContract) -> Result<Option<ReverificationAlert>> {
        let bytecode = self.provider
            .get_code(monitored.address, None)
            .await
            .context("Failed to fetch contract bytecode")?;
        
        let current_hash = self.hash_bytecode(&bytecode);
        
        if current_hash != monitored.original_bytecode_hash {
            warn!("Bytecode changed for contract {:?}", monitored.address);
            
            return Ok(Some(ReverificationAlert {
                contract_address: monitored.address,
                trigger: ReverificationTrigger::BytecodeChanged {
                    old_hash: monitored.original_bytecode_hash,
                    new_hash: current_hash,
                },
                severity: AlertSeverity::Critical,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                action_required: "Contract bytecode has changed. Immediate reverification required before further use.".to_string(),
                webhook_sent: false,
            }));
        }
        
        Ok(None)
    }
    
    /// Check if proxy implementation has been upgraded
    async fn check_proxy_upgrade(&self, monitored: &MonitoredContract) -> Result<Option<ReverificationAlert>> {
        if let Some(old_impl) = monitored.implementation_address {
            let current_impl = self.get_implementation_address(monitored.address).await?;
            
            if let Some(new_impl) = current_impl {
                if old_impl != new_impl {
                    warn!("Proxy upgraded for contract {:?}: {:?} -> {:?}", 
                         monitored.address, old_impl, new_impl);
                    
                    return Ok(Some(ReverificationAlert {
                        contract_address: monitored.address,
                        trigger: ReverificationTrigger::ProxyUpgraded {
                            old_implementation: old_impl,
                            new_implementation: new_impl,
                        },
                        severity: AlertSeverity::Critical,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        action_required: "Proxy implementation upgraded. New implementation must be analyzed immediately.".to_string(),
                        webhook_sent: false,
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Check if TVL exceeds threshold
    async fn check_tvl_threshold(&self, monitored: &MonitoredContract, threshold: u128) -> Result<Option<ReverificationAlert>> {
        // Simplified: Check contract ETH balance as TVL proxy
        // In production, integrate with DeFi TVL oracles (DefiLlama, etc.)
        let balance = self.provider
            .get_balance(monitored.address, None)
            .await
            .context("Failed to fetch contract balance")?;
        
        if balance > U256::from(threshold) {
            // Only alert if this is the first time crossing threshold
            if monitored.last_tvl_check.is_none() || monitored.last_tvl_check.unwrap() <= U256::from(threshold) {
                info!("TVL threshold exceeded for contract {:?}: {} > {}", 
                     monitored.address, balance, threshold);
                
                return Ok(Some(ReverificationAlert {
                    contract_address: monitored.address,
                    trigger: ReverificationTrigger::TvlThresholdExceeded {
                        threshold: U256::from(threshold),
                        current_tvl: balance,
                    },
                    severity: AlertSeverity::High,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    action_required: format!(
                        "Contract TVL exceeds ${} threshold. Enhanced security review recommended.",
                        threshold / 1_000_000_000_000_000_000 // Convert wei to ETH
                    ),
                    webhook_sent: false,
                }));
            }
        }
        
        Ok(None)
    }
    
    /// Check if certificate has expired
    async fn check_time_expiration(&self, monitored: &MonitoredContract) -> Result<Option<ReverificationAlert>> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expires_at = monitored.latest_certificate.expires_at;
        
        // Alert 7 days before expiration
        let warning_threshold = expires_at.saturating_sub(7 * 24 * 60 * 60);
        
        if current_time >= expires_at {
            return Ok(Some(ReverificationAlert {
                contract_address: monitored.address,
                trigger: ReverificationTrigger::TimeExpired {
                    expires_at,
                    current_time,
                },
                severity: AlertSeverity::High,
                timestamp: current_time,
                action_required: "Security certificate has expired. Reverification required.".to_string(),
                webhook_sent: false,
            }));
        } else if current_time >= warning_threshold {
            return Ok(Some(ReverificationAlert {
                contract_address: monitored.address,
                trigger: ReverificationTrigger::TimeExpired {
                    expires_at,
                    current_time,
                },
                severity: AlertSeverity::Medium,
                timestamp: current_time,
                action_required: format!(
                    "Security certificate expires in {} days. Schedule reverification.",
                    (expires_at - current_time) / (24 * 60 * 60)
                ),
                webhook_sent: false,
            }));
        }
        
        Ok(None)
    }
    
    /// Check if any monitored dependencies have changed
    async fn check_dependency_changes(&self, monitored: &MonitoredContract) -> Result<Option<ReverificationAlert>> {
        for dep_address in &monitored.monitored_dependencies {
            let bytecode = self.provider
                .get_code(*dep_address, None)
                .await
                .context("Failed to fetch dependency bytecode")?;
            
            // In production, maintain hash database of dependency bytecodes
            // For now, just check if dependency still exists
            if bytecode.is_empty() {
                return Ok(Some(ReverificationAlert {
                    contract_address: monitored.address,
                    trigger: ReverificationTrigger::DependencyChanged {
                        dependency: *dep_address,
                        change_type: "Dependency contract destructed".to_string(),
                    },
                    severity: AlertSeverity::Critical,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    action_required: format!(
                        "Dependency contract {:?} has been destroyed. Immediate security review required.",
                        dep_address
                    ),
                    webhook_sent: false,
                }));
            }
        }
        
        Ok(None)
    }
    
    /// Send alert via configured webhooks
    async fn send_alert(&self, monitored: &MonitoredContract, mut alert: ReverificationAlert) -> Result<()> {
        info!("Sending alert for contract {:?}: {:?}", monitored.address, alert.trigger);
        
        for webhook_url in &monitored.monitoring_config.alert_webhooks {
            match self.send_webhook(webhook_url, &alert).await {
                Ok(_) => {
                    info!("Alert sent to webhook: {}", webhook_url);
                    alert.webhook_sent = true;
                }
                Err(e) => {
                    error!("Failed to send webhook to {}: {}", webhook_url, e);
                }
            }
        }
        
        // Store alert in database (TODO: implement persistence)
        // store_alert(&alert)?;
        
        Ok(())
    }
    
    /// Send HTTP POST to webhook URL
    async fn send_webhook(&self, url: &str, alert: &ReverificationAlert) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .post(url)
            .json(alert)
            .send()
            .await
            .context("Failed to send webhook")?;
        
        if !response.status().is_success() {
            anyhow::bail!("Webhook returned error status: {}", response.status());
        }
        
        Ok(())
    }
    
    // === HELPER METHODS ===
    
    fn hash_bytecode(&self, bytecode: &Bytes) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(bytecode.as_ref());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Detect if contract is a proxy
    async fn detect_proxy_pattern(&self, address: Address) -> Result<(bool, Option<Address>)> {
        // Check EIP-1967 storage slot for implementation address
        let impl_slot: H256 = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc".parse().unwrap();
        
        let impl_bytes = self.provider
            .get_storage_at(address, impl_slot, None)
            .await
            .context("Failed to read implementation storage slot")?;
        
        if !impl_bytes.is_zero() {
            let impl_address = Address::from_slice(&impl_bytes.as_bytes()[12..32]);
            return Ok((true, Some(impl_address)));
        }
        
        Ok((false, None))
    }
    
    /// Get current implementation address for proxy
    async fn get_implementation_address(&self, proxy: Address) -> Result<Option<Address>> {
        let impl_slot: H256 = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc".parse().unwrap();
        
        let impl_bytes = self.provider
            .get_storage_at(proxy, impl_slot, None)
            .await
            .context("Failed to read implementation storage slot")?;
        
        if impl_bytes.is_zero() {
            return Ok(None);
        }
        
        let impl_address = Address::from_slice(&impl_bytes.as_bytes()[12..32]);
        Ok(Some(impl_address))
    }
    
    /// Extract external dependencies (oracles, bridges, etc.)
    async fn extract_dependencies(&self, _address: Address) -> Result<Vec<Address>> {
        // TODO: Implement static analysis to extract external contract addresses
        // For now, return empty vec
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_monitor_creation() {
        let monitor = ContractLifecycleMonitor::new("http://localhost:8545", 60);
        assert!(monitor.is_ok());
    }
}
