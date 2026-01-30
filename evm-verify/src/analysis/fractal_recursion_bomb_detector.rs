use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FractalRecursionVulnerability {
    SelfSimilarExpansion { description: String, location: usize, confidence: f32 },
    RecursiveStructureExplosion { description: String, location: usize, confidence: f32 },
    NestedDataBomb { description: String, location: usize, confidence: f32 },
}

pub struct FractalRecursionBombDetector {
    bytecode: Vec<u8>,
}

impl FractalRecursionBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<FractalRecursionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern 1: Recursive call with data expansion
            let has_recursive_call = section.windows(20).any(|w| {
                w.contains(&0x30) && (w.contains(&0xF1) || w.contains(&0xFA)) // ADDRESS + CALL/STATICCALL
            });
            let has_calldatacopy = section.contains(&0x37); // CALLDATACOPY
            let has_mstore = section.contains(&0x52); // MSTORE
            let has_calldata_size = section.contains(&0x36); // CALLDATASIZE
            
            if has_recursive_call && (has_calldatacopy || has_mstore) && has_calldata_size {
                vulnerabilities.push(FractalRecursionVulnerability::SelfSimilarExpansion {
                    description: format!("Fractal recursion at PC {}. Self-similar recursive structure expands exponentially. Attack: Small input → massive gas consumption. Fractal geometry: Structure self-similar at all scales. Mandelbrot set: zoom in → same pattern. Here: function calls itself with expanded data. Example: verifyProof(proof) where proof contains sub-proofs, each containing sub-sub-proofs → depth 10 = 2^10 = 1024 calls. Real: Merkle tree proof where each node proof contains child proofs. ZIP bomb equivalent: small compressed → massive decompressed. Mitigation: Limit recursion depth (max 32), bound data expansion factor, or iterate not recurse.", i),
                    location: i,
                    confidence: 0.88,
                });
            }
            
            // Pattern 2: Loop with nested loops (fractal iteration)
            let loop_count = section.windows(20).filter(|w| w.contains(&0x57)).count(); // JUMPI
            let has_mload = section.contains(&0x51); // MLOAD (array access)
            let has_calldataload = section.contains(&0x35); // CALLDATALOAD
            
            if loop_count >= 3 && has_mload && has_calldataload {
                vulnerabilities.push(FractalRecursionVulnerability::NestedDataBomb {
                    description: format!("Nested data bomb at PC {}. Multiple nested loops create fractal iteration space. Attack: for i {{for j {{for k {{...}}}}}} → O(N^depth) complexity. Example: N=100, depth=3 → 1M iterations. Depth=4 → 100M iterations = DOS. Fractal: Each iteration spawns N child iterations. Koch snowflake: each segment becomes 4 segments → exponential perimeter growth. Real: Multi-dimensional array processing, graph traversal without visited set, nested struct unpacking. Mitigation: Limit loop nesting depth to 2, bound total iterations, or use iterative algorithms with explicit stack.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
            
            // Pattern 3: Tree/graph expansion without depth limit
            let has_keccak = section.contains(&0x20); // SHA3 (hash tree nodes)
            let has_loop = section.windows(15).any(|w| w.contains(&0x56) || w.contains(&0x57));
            let no_depth_bound = !section.windows(15).any(|w| {
                w.contains(&0x10) && w.contains(&0x60) // LT + PUSH1 (depth < MAX)
            });
            
            if has_keccak && has_loop && no_depth_bound && has_recursive_call {
                vulnerabilities.push(FractalRecursionVulnerability::RecursiveStructureExplosion {
                    description: format!("Recursive structure explosion at PC {}. Tree/graph expands fractally without bounds. Attack: Binary tree of depth D has 2^D nodes. Attacker provides deep tree → gas bomb. Example: Merkle proof verification where each proof element can itself be a Merkle root requiring sub-proof. Fractal trees: Each branch spawns branches → self-similar at all scales. Real: NFT metadata where each token URI points to JSON with nested token URIs. Or: Recursive data structures in Solidity (struct containing array of same struct). Mitigation: Maximum tree depth (32), iterative traversal with explicit stack, or reject recursive structures.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
}
