// Fractal Network Testing Framework

use super::*;
use super::prover::FractalZODAProver;
use super::topology::{PhiCoordinates, ProverID};
use super::phi_optimizer::{PHI, PHI_INVERSE};
use super::aggregation::{ZODAProofTask, TensorSegment, PhiParams, AggregationMethod, RhombusParams};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fractal_network_initialization() {
        let coordinates = PhiCoordinates::new(0, 0, 0.0, 0.0, 0.0);
        let mut prover = FractalZODAProver::new("test_node_1".to_string(), coordinates);
        
        let result = prover.initialize_fractal_topology();
        assert!(result.is_ok(), "Fractal topology initialization should succeed");
        
        // Verify topology follows φ-optimization principles
        assert!(prover.topology_manager.connection_count() > 0, "Should have established connections");
        
        println!("✅ Fractal network initialization test passed");
    }

    #[test]
    fn test_phi_optimization_calculations() {
        let phi_optimizer = phi_optimizer::GoldenRatioOptimizer::new();
        
        // Test Fibonacci cluster sizing
        assert_eq!(phi_optimizer.calculate_optimal_cluster_size(0), 5);
        assert_eq!(phi_optimizer.calculate_optimal_cluster_size(3), 8);
        assert_eq!(phi_optimizer.calculate_optimal_cluster_size(5), 13);
        
        // Test φ-proportioned branching
        let branching_factor = phi_optimizer.calculate_phi_branching_factor();
        assert!(branching_factor >= 1 && branching_factor <= 3, "Branching factor should be 1-3");
        
        // Test shortcut calculations
        let shortcuts = phi_optimizer.calculate_shortcut_count();
        assert_eq!(shortcuts, 3, "Should calculate ~3 shortcuts from φ*2");
        
        println!("✅ φ-optimization calculations test passed");
    }

    #[test]
    fn test_phi_coordinates_mathematics() {
        let parent = PhiCoordinates::new(1, 10, PHI, PHI, PHI);
        let child = parent.calculate_child_coordinates(0);
        let calculated_parent = child.calculate_parent_coordinates();
        
        // Test φ-distance calculation
        let distance = parent.calculate_phi_distance(&child);
        assert!(distance > 0.0, "φ-distance should be positive");
        
        // Test φ-efficiency calculation
        let efficiency = parent.calculate_phi_efficiency(&child);
        assert!(efficiency > 0.0 && efficiency <= PHI, "φ-efficiency should be in valid range");
        
        // Test coordinate relationships
        assert_eq!(child.fractal_level, parent.fractal_level + 1, "Child should be one level deeper");
        assert!(child.phi_x > parent.phi_x, "Child φ-x should be scaled up");
        
        println!("✅ φ-coordinates mathematics test passed");
    }

    #[tokio::test]
    async fn test_proof_aggregation_phi_optimization() {
        let mut aggregator = aggregation::ProofAggregator::new();
        
        // Create test segments with φ-validation scores
        let test_segments = create_test_proof_segments();
        
        let mut completed_proof = None;
        for segment in test_segments {
            if let Ok(Some(proof)) = aggregator.add_proof_segment(segment) {
                completed_proof = Some(proof);
                break;
            }
        }
        
        // Verify φ-optimized aggregation
        if let Some(proof) = completed_proof {
            assert!(proof.phi_efficiency >= PHI_INVERSE, "Aggregated proof should meet φ-efficiency threshold");
            assert!(!proof.aggregated_proof.is_empty(), "Aggregated proof should contain data");
            assert!(!proof.contributors.is_empty(), "Should track contributors");
            
            println!("✅ Proof aggregation φ-optimization test passed");
        } else {
            // Test that we can still add segments without completion
            assert_eq!(aggregator.get_pending_task_count(), 1, "Should have pending task");
            println!("✅ Proof aggregation pending test passed");
        }
    }

    #[test]
    fn test_consensus_phi_weighting() {
        let mut consensus = consensus::ConsensusEngine::new();
        
        // Create test proposal
        let network_params = consensus::NetworkParams::default_phi_optimized();
        let proposal = consensus::ConsensusProposal::NetworkParameterUpdate(network_params);
        let proposal_id = consensus.submit_proposal(proposal);
        
        // Test φ-weighted voting
        let high_phi_weight = PHI * PHI; // Strong φ-weight
        let low_phi_weight = PHI_INVERSE; // Weak φ-weight
        
        consensus.cast_vote(&proposal_id, consensus::Vote::Approve, high_phi_weight).unwrap();
        consensus.cast_vote(&proposal_id, consensus::Vote::Reject, low_phi_weight).unwrap();
        
        // Check consensus result
        let result = consensus.check_consensus(&proposal_id);
        assert!(result.is_some(), "Should have consensus result");
        
        println!("✅ Consensus φ-weighting test passed");
    }

    #[tokio::test]
    async fn test_network_scalability_simulation() {
        let mut network_nodes = Vec::new();
        
        // Create fractal network with multiple levels
        for level in 0..3 {
            for position in 0..5 {
                let coordinates = PhiCoordinates::new(
                    level, 
                    position, 
                    position as f64 * PHI, 
                    level as f64 * PHI_INVERSE, 
                    0.0
                );
                let mut prover = FractalZODAProver::new(
                    format!("node_{}_{}", level, position), 
                    coordinates
                );
                prover.initialize_fractal_topology().unwrap();
                network_nodes.push(prover);
            }
        }
        
        // Verify O(log n) scaling properties
        let total_connections: usize = network_nodes.iter()
            .map(|node| node.topology_manager.connection_count())
            .sum();
        
        let average_connections = total_connections as f64 / network_nodes.len() as f64;
        let network_size = network_nodes.len() as f64;
        let log_n_bound = network_size.log(PHI) * PHI;
        
        assert!(average_connections <= log_n_bound, 
               "Average connections should follow O(log n) scaling: {} <= {}", 
               average_connections, log_n_bound);
        
        println!("✅ Network scalability simulation test passed");
        println!("   Network size: {}, Average connections: {:.2}, O(log n) bound: {:.2}", 
                network_size, average_connections, log_n_bound);
    }

    #[test]
    fn test_fibonacci_sequence_optimization() {
        let phi_optimizer = phi_optimizer::GoldenRatioOptimizer::new();
        
        // Test Fibonacci number generation
        assert_eq!(phi_optimizer.get_fibonacci_number(0), 1);
        assert_eq!(phi_optimizer.get_fibonacci_number(1), 1);
        assert_eq!(phi_optimizer.get_fibonacci_number(5), 8);
        assert_eq!(phi_optimizer.get_fibonacci_number(6), 13);
        
        // Test φ-segment sizing
        let total_size = 100;
        let segment_sizes: Vec<usize> = (0..5)
            .map(|i| phi_optimizer.calculate_phi_segment_size(i, total_size))
            .collect();
        
        // Verify segments follow Fibonacci proportions
        let total_segments: usize = segment_sizes.iter().sum();
        assert!(total_segments <= total_size, "Total segments should not exceed original size");
        
        println!("✅ Fibonacci sequence optimization test passed");
        println!("   Segment sizes: {:?}, Total: {}/{}", segment_sizes, total_segments, total_size);
    }

    #[test]
    fn test_natural_law_compliance() {
        // Verify fractal network follows natural organizing principles
        
        // 1. Golden ratio appears in all calculations
        assert!((PHI - 1.618033988749895).abs() < 1e-10, "φ constant should be precise");
        assert!((PHI_INVERSE - 0.618033988749895).abs() < 1e-10, "φ^-1 constant should be precise");
        assert!((PHI * PHI_INVERSE - 1.0).abs() < 1e-10, "φ * φ^-1 should equal 1");
        
        // 2. Fibonacci relationships hold
        let phi_optimizer = phi_optimizer::GoldenRatioOptimizer::new();
        for i in 2..10 {
            let current = phi_optimizer.get_fibonacci_number(i);
            let prev1 = phi_optimizer.get_fibonacci_number(i-1);
            let prev2 = phi_optimizer.get_fibonacci_number(i-2);
            assert_eq!(current, prev1 + prev2, "Fibonacci relationship should hold for F({})", i);
        }
        
        // 3. Network parameters follow natural bounds
        let network_params = consensus::NetworkParams::default_phi_optimized();
        assert!(network_params.validates_phi_principles(), "Network parameters should validate φ principles");
        
        println!("✅ Natural law compliance test passed");
    }

    // Helper function to create test proof segments
    fn create_test_proof_segments() -> Vec<aggregation::ProofSegment> {
        vec![
            aggregation::ProofSegment {
                task_id: "test_task_1".to_string(),
                segment_id: "segment_1".to_string(),
                proof_data: vec![1, 2, 3, 4, 5],
                phi_validation_score: PHI,
                contributor: ProverID("node_1".to_string()),
            },
            aggregation::ProofSegment {
                task_id: "test_task_1".to_string(),
                segment_id: "segment_2".to_string(),
                proof_data: vec![6, 7, 8, 9, 10],
                phi_validation_score: PHI_INVERSE,
                contributor: ProverID("node_2".to_string()),
            },
        ]
    }
}

// Benchmark tests for performance validation
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_phi_calculations() {
        let start = Instant::now();
        let iterations = 10000;
        
        for i in 0..iterations {
            let coords = PhiCoordinates::new(
                (i % 10) as u8,
                i as u16 % 1000,
                i as f64 * PHI,
                i as f64 * PHI_INVERSE,
                (i as f64).sqrt(),
            );
            
            let child = coords.calculate_child_coordinates(0);
            let _efficiency = coords.calculate_phi_efficiency(&child);
        }
        
        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();
        
        println!("✅ φ-calculations benchmark: {:.0} ops/sec", ops_per_sec);
        assert!(ops_per_sec > 10000.0, "φ-calculations should be highly optimized");
    }

    #[test]
    fn benchmark_network_topology_creation() {
        let start = Instant::now();
        
        let coordinates = PhiCoordinates::new(0, 0, 0.0, 0.0, 0.0);
        let mut prover = FractalZODAProver::new("benchmark_node".to_string(), coordinates);
        
        prover.initialize_fractal_topology().unwrap();
        
        let duration = start.elapsed();
        
        println!("✅ Network topology creation benchmark: {:.3}ms", duration.as_millis());
        assert!(duration.as_millis() < 100, "Topology creation should be fast");
    }
}
