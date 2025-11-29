// Proof-of-Work Spam Prevention
// Trustless Manifesto: Spam resistance without centralized gatekeepers

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Difficulty levels (leading zero bits required)
#[derive(Debug, Clone, Copy)]
pub enum Difficulty {
    VeryEasy = 4,    // ~16 attempts average
    Easy = 8,        // ~256 attempts
    Medium = 12,     // ~4,096 attempts
    Hard = 16,       // ~65,536 attempts
    VeryHard = 20,   // ~1,048,576 attempts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWork {
    pub challenge: Vec<u8>,
    pub nonce: u64,
    pub difficulty: u8,
}

impl ProofOfWork {
    /// Verify proof-of-work (anyone can verify, no trust needed)
    pub fn verify(&self, data: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&self.challenge);
        hasher.update(&self.nonce.to_le_bytes());
        let hash = hasher.finalize();
        
        // Count leading zero bits
        let leading_zeros = count_leading_zero_bits(&hash);
        leading_zeros >= self.difficulty as usize
    }
    
    /// Generate proof-of-work (CPU-intensive, prevents spam)
    pub fn generate(data: &[u8], difficulty: Difficulty) -> Self {
        let challenge: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let difficulty_bits = difficulty as u8;
        
        let mut nonce = 0u64;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(&challenge);
            hasher.update(&nonce.to_le_bytes());
            let hash = hasher.finalize();
            
            let leading_zeros = count_leading_zero_bits(&hash);
            if leading_zeros >= difficulty_bits as usize {
                return ProofOfWork {
                    challenge,
                    nonce,
                    difficulty: difficulty_bits,
                };
            }
            
            nonce += 1;
            
            // Safety: prevent infinite loop
            if nonce > 10_000_000 {
                panic!("PoW difficulty too high");
            }
        }
    }
}

/// Count leading zero bits in hash
fn count_leading_zero_bits(hash: &[u8]) -> usize {
    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pow_easy() {
        let data = b"test task";
        let pow = ProofOfWork::generate(data, Difficulty::VeryEasy);
        assert!(pow.verify(data));
    }
    
    #[test]
    fn test_pow_invalid_nonce() {
        let data = b"test task";
        let mut pow = ProofOfWork::generate(data, Difficulty::Easy);
        pow.nonce += 1; // Invalidate
        assert!(!pow.verify(data));
    }
}
