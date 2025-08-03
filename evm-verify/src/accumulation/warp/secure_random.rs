//! Cryptographically secure random number generation for zkEVM proofs
//!
//! This module provides entropy sources and random generation that resist
//! prediction attacks and maintain cryptographic security guarantees.

use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::Mutex;

use super::secure_field::{SecureField, SecureFieldError};

/// Cryptographically secure random number generator for zkEVM operations
/// 
/// Features:
/// - ChaCha20 stream cipher for cryptographic security
/// - Forward secrecy through state zeroization
/// - Entropy collection from multiple sources
/// - Resistance to prediction and state recovery attacks
#[derive(ZeroizeOnDrop)]
pub struct SecureRng {
    /// Primary CSPRNG using ChaCha20
    rng: ChaCha20Rng,
    /// Entropy pool for reseeding
    entropy_pool: [u8; 64],
    /// Counter for periodic reseeding
    reseed_counter: u64,
}

impl SecureRng {
    /// Create new secure RNG with proper entropy collection
    pub fn new() -> Result<Self, SecureRandomError> {
        let entropy = Self::collect_entropy()?;
        let seed = Self::derive_seed(&entropy);
        
        Ok(SecureRng {
            rng: ChaCha20Rng::from_seed(seed),
            entropy_pool: entropy,
            reseed_counter: 0,
        })
    }

    /// Create deterministic RNG from seed (for testing only)
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecureRng {
            rng: ChaCha20Rng::from_seed(seed),
            entropy_pool: [0u8; 64],
            reseed_counter: 0,
        }
    }

    /// Generate cryptographically secure random field element
    pub fn random_field(&mut self) -> SecureField {
        self.check_reseed();
        SecureField::random_secure(&mut self.rng)
    }

    /// Generate secure random bytes
    pub fn random_bytes(&mut self, dest: &mut [u8]) {
        self.check_reseed();
        self.rng.fill_bytes(dest);
    }

    /// Generate random challenge for Fiat-Shamir transform
    pub fn random_challenge(&mut self) -> [u8; 32] {
        self.check_reseed();
        let mut challenge = [0u8; 32];
        self.rng.fill_bytes(&mut challenge);
        challenge
    }

    /// Generate random query indices for FRI
    pub fn random_query_indices(&mut self, domain_size: usize, query_count: usize) -> Vec<usize> {
        self.check_reseed();
        
        let mut indices = Vec::with_capacity(query_count);
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = query_count * 10;

        while indices.len() < query_count && attempts < MAX_ATTEMPTS {
            let index = (self.rng.next_u64() as usize) % domain_size;
            
            // Ensure uniqueness
            if !indices.contains(&index) {
                indices.push(index);
            }
            
            attempts += 1;
        }

        // Fill remaining slots if we couldn't generate enough unique indices
        while indices.len() < query_count {
            let index = indices.len() % domain_size;
            if !indices.contains(&index) {
                indices.push(index);
            }
        }

        indices
    }

    /// Generate batch of random field elements efficiently
    pub fn random_field_batch(&mut self, count: usize) -> Vec<SecureField> {
        self.check_reseed();
        (0..count).map(|_| SecureField::random_secure(&mut self.rng)).collect()
    }

    /// Collect entropy from multiple sources
    fn collect_entropy() -> Result<[u8; 64], SecureRandomError> {
        let mut entropy = [0u8; 64];
        
        // Primary entropy from OS
        getrandom::getrandom(&mut entropy[0..32])
            .map_err(|_| SecureRandomError::EntropyCollectionFailed)?;

        // Additional entropy from timing
        let timing_entropy = Self::collect_timing_entropy();
        entropy[32..48].copy_from_slice(&timing_entropy);

        // Hash-based entropy mixing
        let hash_entropy = Self::collect_hash_entropy();
        entropy[48..64].copy_from_slice(&hash_entropy);

        Ok(entropy)
    }

    /// Collect timing-based entropy (weak but adds unpredictability)
    fn collect_timing_entropy() -> [u8; 16] {
        let mut hasher = Sha3_256::new();
        
        // Collect multiple timing samples
        for _ in 0..8 {
            let start = std::time::Instant::now();
            
            // Perform some computation to get timing variation
            let mut sum = 0u64;
            for i in 0..1000 {
                sum = sum.wrapping_add(i.wrapping_mul(i));
            }
            
            let elapsed = start.elapsed().as_nanos();
            hasher.update(&elapsed.to_le_bytes());
            hasher.update(&sum.to_le_bytes());
        }

        let hash = hasher.finalize();
        let mut result = [0u8; 16];
        result.copy_from_slice(&hash[0..16]);
        result
    }

    /// Collect hash-based entropy
    fn collect_hash_entropy() -> [u8; 16] {
        let mut hasher = Sha3_256::new();
        
        // Mix in various sources
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(&std::thread::current().id().as_u64().to_le_bytes());
        
        // Add current time with nanosecond precision
        if let Ok(system_time) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            hasher.update(&system_time.as_nanos().to_le_bytes());
        }

        let hash = hasher.finalize();
        let mut result = [0u8; 16];
        result.copy_from_slice(&hash[16..32]);
        result
    }

    /// Derive cryptographic seed from entropy
    fn derive_seed(entropy: &[u8; 64]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ZODA_WARP_SEED_DERIVATION_V1");
        hasher.update(entropy);
        
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash);
        seed
    }

    /// Check if reseeding is needed and perform if necessary
    fn check_reseed(&mut self) {
        self.reseed_counter += 1;
        
        // Reseed every 1M operations for forward secrecy
        if self.reseed_counter >= 1_000_000 {
            if let Ok(new_entropy) = Self::collect_entropy() {
                let new_seed = Self::derive_seed(&new_entropy);
                self.rng = ChaCha20Rng::from_seed(new_seed);
                self.entropy_pool = new_entropy;
                self.reseed_counter = 0;
            }
        }
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new().expect("Failed to create secure RNG")
    }
}

// Implement CryptoRng marker trait
impl CryptoRng for SecureRng {}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.check_reseed();
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.check_reseed();
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.check_reseed();
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.check_reseed();
        self.rng.try_fill_bytes(dest)
    }
}

/// Global secure RNG instance (thread-safe)
static GLOBAL_RNG: Mutex<Option<SecureRng>> = Mutex::new(None);

/// Get global secure RNG instance
pub fn global_secure_rng() -> Result<std::sync::MutexGuard<'static, SecureRng>, SecureRandomError> {
    let mut guard = GLOBAL_RNG.lock().map_err(|_| SecureRandomError::LockError)?;
    
    if guard.is_none() {
        *guard = Some(SecureRng::new()?);
    }
    
    Ok(std::sync::MutexGuard::map(guard, |opt| opt.as_mut().unwrap()))
}

/// Fiat-Shamir challenge generation for non-interactive proofs
pub struct FiatShamirChallenger {
    hasher: Sha3_256,
    challenge_count: u32,
}

impl FiatShamirChallenger {
    /// Create new Fiat-Shamir challenger
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"FIAT_SHAMIR_ZODA_WARP_V1");
        hasher.update(protocol_name);
        
        FiatShamirChallenger {
            hasher,
            challenge_count: 0,
        }
    }

    /// Add commitment to transcript
    pub fn add_commitment(&mut self, commitment: &[u8]) {
        self.hasher.update(b"COMMITMENT");
        self.hasher.update(&(commitment.len() as u32).to_le_bytes());
        self.hasher.update(commitment);
    }

    /// Add field element to transcript
    pub fn add_field_element(&mut self, element: &SecureField) {
        self.hasher.update(b"FIELD_ELEMENT");
        let bytes = element.to_bytes_secure();
        self.hasher.update(&bytes);
    }

    /// Generate next challenge as field element
    pub fn challenge_field(&mut self) -> SecureField {
        self.hasher.update(b"CHALLENGE_FIELD");
        self.hasher.update(&self.challenge_count.to_le_bytes());
        self.challenge_count += 1;

        let hash = self.hasher.clone().finalize();
        
        // Convert hash to field element (may need multiple attempts)
        for i in 0..8 {
            let mut bytes = [0u8; 32];
            let start_idx = (i * 4) % 24;
            bytes[0..8].copy_from_slice(&hash[start_idx..start_idx + 8]);
            
            if let Ok(field) = SecureField::from_bytes_secure(&bytes) {
                return field;
            }
        }

        // Fallback: use deterministic field element
        SecureField::new(ark_bls12_381::Fr::from(self.challenge_count as u64))
            .unwrap_or(SecureField::one())
    }

    /// Generate challenge bytes
    pub fn challenge_bytes(&mut self, length: usize) -> Vec<u8> {
        self.hasher.update(b"CHALLENGE_BYTES");
        self.hasher.update(&(length as u32).to_le_bytes());
        self.hasher.update(&self.challenge_count.to_le_bytes());
        self.challenge_count += 1;

        let hash = self.hasher.clone().finalize();
        
        if length <= 32 {
            hash[0..length].to_vec()
        } else {
            // For longer outputs, rehash iteratively
            let mut result = Vec::with_capacity(length);
            let mut current_hash = hash.to_vec();
            
            while result.len() < length {
                let needed = std::cmp::min(32, length - result.len());
                result.extend_from_slice(&current_hash[0..needed]);
                
                if result.len() < length {
                    let mut hasher = Sha3_256::new();
                    hasher.update(&current_hash);
                    current_hash = hasher.finalize().to_vec();
                }
            }
            
            result
        }
    }
}

/// Errors for secure random generation
#[derive(Debug, Clone)]
pub enum SecureRandomError {
    EntropyCollectionFailed,
    LockError,
    InvalidSeed,
}

impl std::fmt::Display for SecureRandomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureRandomError::EntropyCollectionFailed => write!(f, "Failed to collect system entropy"),
            SecureRandomError::LockError => write!(f, "Failed to acquire RNG lock"),
            SecureRandomError::InvalidSeed => write!(f, "Invalid seed provided"),
        }
    }
}

impl std::error::Error for SecureRandomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng_creation() {
        let mut rng = SecureRng::new().unwrap();
        
        // Generate some random data
        let field1 = rng.random_field();
        let field2 = rng.random_field();
        
        // Should be different (extremely high probability)
        assert!(!bool::from(field1.ct_eq(&field2)));
    }

    #[test]
    fn test_deterministic_rng() {
        let seed = [42u8; 32];
        let mut rng1 = SecureRng::from_seed(seed);
        let mut rng2 = SecureRng::from_seed(seed);
        
        // Same seed should produce same output
        let field1 = rng1.random_field();
        let field2 = rng2.random_field();
        
        assert!(bool::from(field1.ct_eq(&field2)));
    }

    #[test]
    fn test_query_indices_generation() {
        let mut rng = SecureRng::new().unwrap();
        let indices = rng.random_query_indices(1000, 10);
        
        assert_eq!(indices.len(), 10);
        
        // All indices should be in range
        assert!(indices.iter().all(|&i| i < 1000));
        
        // Should be unique (for reasonable domain size)
        let mut sorted_indices = indices.clone();
        sorted_indices.sort();
        sorted_indices.dedup();
        assert_eq!(sorted_indices.len(), indices.len());
    }

    #[test]
    fn test_fiat_shamir_challenger() {
        let mut challenger1 = FiatShamirChallenger::new(b"test_protocol");
        let mut challenger2 = FiatShamirChallenger::new(b"test_protocol");
        
        // Same inputs should produce same challenges
        challenger1.add_commitment(b"commitment_data");
        challenger2.add_commitment(b"commitment_data");
        
        let challenge1 = challenger1.challenge_field();
        let challenge2 = challenger2.challenge_field();
        
        assert!(bool::from(challenge1.ct_eq(&challenge2)));
    }

    #[test]
    fn test_challenge_bytes() {
        let mut challenger = FiatShamirChallenger::new(b"test_protocol");
        challenger.add_commitment(b"some_commitment");
        
        let bytes_32 = challenger.challenge_bytes(32);
        assert_eq!(bytes_32.len(), 32);
        
        let bytes_64 = challenger.challenge_bytes(64);
        assert_eq!(bytes_64.len(), 64);
    }

    #[test]
    fn test_rng_reseeding() {
        let mut rng = SecureRng::new().unwrap();
        
        // Force reseed by setting counter high
        rng.reseed_counter = 999_999;
        
        let field_before = rng.random_field();
        let field_after = rng.random_field(); // Should trigger reseed
        
        // Counter should be reset after reseed
        assert!(rng.reseed_counter < 999_999);
    }
}
