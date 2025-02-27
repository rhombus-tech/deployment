use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use ethers::types::Bytes;
use std::time::Duration;
use hex;

/// Etherscan API client for fetching contract bytecode
pub struct EtherscanClient {
    api_key: String,
    network: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: String,
}

impl EtherscanClient {
    /// Create a new Etherscan client
    pub fn new(api_key: String, network: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            api_key,
            network: network.to_string(),
            client,
        }
    }
    
    /// Get the base URL for the Etherscan API based on the network
    fn get_base_url(&self) -> String {
        match self.network.as_str() {
            "mainnet" => "https://api.etherscan.io/api".to_string(),
            "goerli" => "https://api-goerli.etherscan.io/api".to_string(),
            "sepolia" => "https://api-sepolia.etherscan.io/api".to_string(),
            "arbitrum" => "https://api.arbiscan.io/api".to_string(),
            "optimism" => "https://api-optimistic.etherscan.io/api".to_string(),
            "polygon" => "https://api.polygonscan.com/api".to_string(),
            _ => format!("https://api-{}.etherscan.io/api", self.network),
        }
    }
    
    /// Fetch contract bytecode from Etherscan
    pub async fn get_contract_bytecode(&self, address: &str) -> Result<Bytes> {
        let url = self.get_base_url();
        
        let response = self.client
            .get(&url)
            .query(&[
                ("module", "proxy"),
                ("action", "eth_getCode"),
                ("address", address),
                ("tag", "latest"),
                ("apikey", &self.api_key),
            ])
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(anyhow!("Etherscan API request failed: {}", response.status()));
        }
        
        // Try to parse as EtherscanResponse first
        let response_text = response.text().await?;
        
        // Check if the response is a direct hex string (some API endpoints return this format)
        if response_text.starts_with("\"0x") && response_text.ends_with("\"") {
            // Remove quotes and convert hex string to Bytes
            let bytecode_hex = response_text.trim_matches('"').trim_start_matches("0x");
            let bytecode = hex::decode(bytecode_hex)?;
            return Ok(Bytes::from(bytecode));
        }
        
        // Try to parse as JSON
        match serde_json::from_str::<EtherscanResponse>(&response_text) {
            Ok(etherscan_response) => {
                if etherscan_response.status != "1" {
                    return Err(anyhow!("Etherscan API error: {}", etherscan_response.message));
                }
                
                // The result is a hex string starting with "0x"
                let bytecode_hex = etherscan_response.result;
                if bytecode_hex == "0x" {
                    return Err(anyhow!("Contract at address {} has no bytecode (might be an EOA or unverified contract)", address));
                }
                
                // Convert hex string to Bytes
                let bytecode_hex = bytecode_hex.trim_start_matches("0x");
                let bytecode = hex::decode(bytecode_hex)?;
                
                Ok(Bytes::from(bytecode))
            },
            Err(_) => {
                // If we can't parse as EtherscanResponse, try to parse as direct result
                if response_text.starts_with("0x") {
                    let bytecode_hex = response_text.trim_start_matches("0x");
                    let bytecode = hex::decode(bytecode_hex)?;
                    return Ok(Bytes::from(bytecode));
                }
                
                Err(anyhow!("Failed to parse Etherscan API response: {}", response_text))
            }
        }
    }
}
