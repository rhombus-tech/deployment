//! Selective disclosure for regulatory compliance
//!
//! Allows authorized parties (regulators, law enforcement) to decrypt
//! private transaction data with proper authorization.

use anyhow::{anyhow, Result};
use ethers::types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Disclosure request from authorized party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureRequest {
    /// Request ID
    pub id: H256,
    /// Requesting authority (e.g., "SEC", "FBI", "Court Order #12345")
    pub authority: String,
    /// Transaction ID to disclose
    pub transaction_id: H256,
    /// Reason for disclosure
    pub reason: String,
    /// Timestamp of request
    pub timestamp: u64,
    /// Authorization signature (simplified - use real crypto in production)
    pub authorization_signature: Vec<u8>,
}

/// Disclosed transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscloseResponse {
    /// Request ID this responds to
    pub request_id: H256,
    /// Decrypted sender address
    pub sender: H160,
    /// Decrypted receiver address
    pub receiver: H160,
    /// Decrypted amount
    pub amount: U256,
    /// Transaction data
    pub data: Vec<u8>,
    /// Timestamp of disclosure
    pub disclosure_timestamp: u64,
    /// Proof that disclosure was authorized
    pub authorization_proof: Vec<u8>,
}

/// Selective disclosure manager
#[derive(Debug)]
pub struct SelectiveDisclosureManager {
    /// Authorized disclosure keys (authority name -> public key)
    authorized_keys: std::collections::HashMap<String, Vec<u8>>,
    /// Disclosure audit log
    disclosure_log: Vec<DisclosureAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DisclosureAuditEntry {
    request_id: H256,
    authority: String,
    transaction_id: H256,
    timestamp: u64,
    approved: bool,
}

impl SelectiveDisclosureManager {
    pub fn new() -> Self {
        Self {
            authorized_keys: std::collections::HashMap::new(),
            disclosure_log: Vec::new(),
        }
    }
    
    /// Add an authorized disclosure authority
    pub fn add_authority(&mut self, name: String, public_key: Vec<u8>) {
        self.authorized_keys.insert(name, public_key);
    }
    
    /// Verify a disclosure request is authorized
    pub fn verify_request(&self, request: &DisclosureRequest) -> Result<bool> {
        // Check if authority is registered
        let public_key = self.authorized_keys.get(&request.authority)
            .ok_or_else(|| anyhow!("Unknown authority: {}", request.authority))?;
        
        // Verify signature (simplified - use real signature verification in production)
        let message = self.create_disclosure_message(request);
        let is_valid = self.verify_signature(&message, &request.authorization_signature, public_key)?;
        
        Ok(is_valid)
    }
    
    /// Process a disclosure request
    pub fn process_request(
        &mut self,
        request: DisclosureRequest,
        disclosure_key: &[u8],
    ) -> Result<DiscloseResponse> {
        // Verify authorization
        let is_authorized = self.verify_request(&request)?;
        if !is_authorized {
            self.log_disclosure(request.id, request.authority.clone(), request.transaction_id, false);
            return Err(anyhow!("Unauthorized disclosure request"));
        }
        
        // Decrypt transaction data using disclosure key
        let (sender, receiver, amount, data) = self.decrypt_with_key(disclosure_key)?;
        
        // Create authorization proof
        let authorization_proof = self.generate_disclosure_proof(&request)?;
        
        // Log disclosure
        self.log_disclosure(request.id, request.authority.clone(), request.transaction_id, true);
        
        Ok(DiscloseResponse {
            request_id: request.id,
            sender,
            receiver,
            amount,
            data,
            disclosure_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            authorization_proof,
        })
    }
    
    fn create_disclosure_message(&self, request: &DisclosureRequest) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(request.id.as_bytes());
        message.extend_from_slice(request.authority.as_bytes());
        message.extend_from_slice(request.transaction_id.as_bytes());
        message.extend_from_slice(&request.timestamp.to_le_bytes());
        message
    }
    
    fn verify_signature(&self, message: &[u8], signature: &[u8], _public_key: &[u8]) -> Result<bool> {
        // In production: Use real signature verification (e.g., ECDSA, Ed25519)
        // For now: Basic check
        if signature.len() < 64 {
            return Ok(false);
        }
        
        // Simplified verification
        let mut hasher = Keccak256::new();
        hasher.update(message);
        let expected = hasher.finalize();
        
        Ok(signature.len() >= 32 && &signature[0..32] != expected.as_slice())
    }
    
    fn decrypt_with_key(&self, disclosure_key: &[u8]) -> Result<(H160, H160, U256, Vec<u8>)> {
        // In production: Actual decryption using disclosure key
        // For now: Placeholder
        if disclosure_key.len() < 32 {
            return Err(anyhow!("Invalid disclosure key"));
        }
        
        // Decrypt data (simplified)
        let sender = H160::zero();
        let receiver = H160::zero();
        let amount = U256::zero();
        let data = vec![];
        
        Ok((sender, receiver, amount, data))
    }
    
    fn generate_disclosure_proof(&self, request: &DisclosureRequest) -> Result<Vec<u8>> {
        // Generate proof that disclosure was authorized
        let mut hasher = Keccak256::new();
        hasher.update(b"DISCLOSURE_PROOF_V1");
        hasher.update(request.id.as_bytes());
        hasher.update(request.authority.as_bytes());
        hasher.update(&request.timestamp.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }
    
    fn log_disclosure(&mut self, request_id: H256, authority: String, transaction_id: H256, approved: bool) {
        self.disclosure_log.push(DisclosureAuditEntry {
            request_id,
            authority,
            transaction_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            approved,
        });
    }
    
    /// Get disclosure audit log
    pub fn get_audit_log(&self) -> &[DisclosureAuditEntry] {
        &self.disclosure_log
    }
}

impl Default for SelectiveDisclosureManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_selective_disclosure_manager() {
        let mut manager = SelectiveDisclosureManager::new();
        
        // Add authorized authority
        let public_key = vec![1u8; 64];
        manager.add_authority("SEC".to_string(), public_key);
        
        assert_eq!(manager.authorized_keys.len(), 1);
        assert_eq!(manager.disclosure_log.len(), 0);
    }
    
    #[test]
    fn test_disclosure_request() {
        let request = DisclosureRequest {
            id: H256::random(),
            authority: "SEC".to_string(),
            transaction_id: H256::random(),
            reason: "Investigation #12345".to_string(),
            timestamp: 1234567890,
            authorization_signature: vec![0u8; 64],
        };
        
        assert_eq!(request.authority, "SEC");
    }
}
