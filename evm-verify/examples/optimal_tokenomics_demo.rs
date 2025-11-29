// Complete FRAC Tokenomics Demonstration
// Shows: Early adopter rewards, staking, vesting, burns, and token appreciation

use evm_verify::fractal_network::{
    FracTokenomics, CompletedProof,
};
use evm_verify::fractal_network::topology::ProverID;
use ethers::types::Address;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  💎 FRAC TOKENOMICS - COMPLETE DEMONSTRATION            ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Initialize tokenomics system at genesis
    let genesis_block = 1000;
    let mut tokenomics = FracTokenomics::new(genesis_block);
    
    println!("📊 Initial State:");
    print_stats(&tokenomics);
    println!();

    // ============================================================
    // SCENARIO 1: Early Adopter (First 100 blocks - Epoch 0)
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  🎯 SCENARIO 1: Early Adopter (Epoch 0 - 10x rewards)   ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    let early_alice = Address::random();
    
    // Alice joins during genesis period
    println!("👤 Alice joins as early adopter...");
    let nft_id = tokenomics.register_genesis_prover(early_alice).unwrap();
    println!("   ✅ Genesis NFT #{} minted", nft_id);
    println!("   🎁 Benefits: 2x rewards FOREVER + zero fees\n");
    
    // Alice completes a proof
    let proof = create_demo_proof("block_1");
    let base_reward = 1000; // 1000 FRAC base
    
    let calculation = tokenomics.calculate_proof_reward(early_alice, &proof, base_reward);
    
    println!("📊 Alice's Reward Calculation:");
    println!("   Base reward:         {} FRAC", calculation.base_reward);
    println!("   Epoch multiplier:    {}x  ← 10x for epoch 0!", calculation.epoch_multiplier);
    println!("   Genesis multiplier:  {}x  ← 2x forever!", calculation.genesis_multiplier);
    println!("   Quality bonus:       {} FRAC", calculation.quality_bonus);
    println!("   Staking boost:       {}x", calculation.staking_boost);
    println!("   ───────────────────────────");
    println!("   💰 Total reward:     {} FRAC", calculation.total_reward);
    println!("   🔥 Burned:           {} FRAC", calculation.burn_amount);
    println!();
    
    // Process reward
    tokenomics.process_reward(early_alice, &calculation);
    
    let early_earnings = calculation.total_reward;
    println!("✅ Alice earned: {} FRAC (vs 1000 base = {}x advantage!)\n", early_earnings, early_earnings / base_reward);
    
    // ============================================================
    // SCENARIO 2: Alice Stakes for Maximum Rewards
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  🔒 SCENARIO 2: Alice Stakes for 4 Years                ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    let stake_amount = 10_000;
    println!("👤 Alice stakes {} FRAC for 4 years...", stake_amount);
    let ve_power = tokenomics.create_stake(early_alice, stake_amount, 4).unwrap();
    println!("   ve_power: {} ({}x multiplier)", ve_power, ve_power / stake_amount);
    println!();
    
    // Alice completes another proof with staking boost
    tokenomics.update_block(genesis_block + 100);
    let proof2 = create_demo_proof("block_2");
    let calculation2 = tokenomics.calculate_proof_reward(early_alice, &proof2, base_reward);
    
    println!("📊 Alice's New Reward (with staking):");
    println!("   Staking boost:       {}x  ← Extra from ve_power!", calculation2.staking_boost);
    println!("   💰 Total reward:     {} FRAC", calculation2.total_reward);
    println!();
    
    tokenomics.process_reward(early_alice, &calculation2);

    // ============================================================
    // SCENARIO 3: Alice Uses Vesting for 5x Multiplier
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  📅 SCENARIO 3: Alice Vests for 24 Months (5x bonus)    ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    let vest_amount = calculation2.total_reward;
    println!("👤 Alice locks {} FRAC for 24 months...", vest_amount);
    let multiplier = tokenomics.create_vesting(early_alice, vest_amount, 24).unwrap();
    println!("   Multiplier: {}x", multiplier);
    println!("   Will receive: {} FRAC after 24 months", (vest_amount as f64 * multiplier) as u64);
    println!("   🎁 Bonus: {} FRAC", (vest_amount as f64 * (multiplier - 1.0)) as u64);
    println!();

    // ============================================================
    // SCENARIO 4: Late Joiner Bob (Epoch 3 - 1.5x rewards)
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  ⏰ SCENARIO 4: Late Joiner Bob (Epoch 3 - 1.5x)        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    // Jump to epoch 3 (300k blocks later)
    tokenomics.update_block(genesis_block + 300_000);
    
    let late_bob = Address::random();
    println!("👤 Bob joins late (epoch 3)...");
    println!("   ❌ No genesis NFT (period ended)");
    println!("   ⏰ Epoch multiplier: 1.5x (vs Alice's 10x)\n");
    
    // Bob completes same proof
    let proof_bob = create_demo_proof("block_bob");
    let calculation_bob = tokenomics.calculate_proof_reward(late_bob, &proof_bob, base_reward);
    
    println!("📊 Bob's Reward Calculation:");
    println!("   Base reward:         {} FRAC", calculation_bob.base_reward);
    println!("   Epoch multiplier:    {}x  ← Only 1.5x (late!)", calculation_bob.epoch_multiplier);
    println!("   Genesis multiplier:  {}x  ← No genesis NFT", calculation_bob.genesis_multiplier);
    println!("   ───────────────────────────");
    println!("   💰 Total reward:     {} FRAC", calculation_bob.total_reward);
    println!();
    
    tokenomics.process_reward(late_bob, &calculation_bob);
    
    // ============================================================
    // COMPARISON: Early vs Late
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  📊 EARLY ADOPTER ADVANTAGE                              ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    println!("Same effort, different rewards:");
    println!();
    println!("Alice (Early Adopter):");
    println!("  Initial reward:      {} FRAC (10x × 2x = 20x)", early_earnings);
    println!("  With staking:        {} FRAC", calculation2.total_reward);
    println!("  After vesting (24mo): {} FRAC (5x multiplier)", (calculation2.total_reward as f64 * 5.0) as u64);
    println!("  ─────────────────────────────────");
    println!("  💎 TOTAL:            ~{} FRAC", 
        early_earnings + calculation2.total_reward + (calculation2.total_reward as f64 * 4.0) as u64);
    println!();
    
    println!("Bob (Late Joiner):");
    println!("  Initial reward:      {} FRAC (1.5x × 1x = 1.5x)", calculation_bob.total_reward);
    println!("  No genesis NFT:      ❌");
    println!("  No early multipliers: ❌");
    println!("  ─────────────────────────────────");
    println!("  💰 TOTAL:            {} FRAC", calculation_bob.total_reward);
    println!();
    
    let advantage = (early_earnings + calculation2.total_reward) / calculation_bob.total_reward;
    println!("🚀 Alice's advantage: {}x more FRAC than Bob!", advantage);
    println!("   (Same work, joined early!)");
    println!();

    // ============================================================
    // TOKEN ECONOMICS SUMMARY
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  💰 TOKEN ECONOMICS SUMMARY                              ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    let stats = tokenomics.get_stats();
    println!("Network Statistics:");
    println!("  Total minted:        {} FRAC", stats.total_minted);
    println!("  Total burned:        {} FRAC", stats.total_burned);
    println!("  Circulating supply:  {} FRAC", stats.circulating_supply);
    println!("  Burn rate:           {:.2}%", stats.burn_rate_percent);
    println!("  Genesis provers:     {}", stats.genesis_provers);
    println!("  Total ve_power:      {}", stats.total_staked_ve);
    println!("  Protocol treasury:   {} FRAC", stats.protocol_treasury);
    println!("  Current epoch:       {}", stats.current_epoch);
    println!("  Epoch multiplier:    {}x", stats.epoch_multiplier);
    println!();

    // ============================================================
    // DEFLATIONARY PROJECTION
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  🔥 DEFLATIONARY PROJECTION (at scale)                   ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    println!("Assuming 1M proofs/month:");
    println!();
    println!("Year 1:");
    println!("  Monthly burns:       600,000 FRAC");
    println!("  Annual burns:        7,200,000 FRAC");
    println!("  Supply reduction:    7.2%");
    println!();
    
    println!("Year 3:");
    println!("  Cumulative burns:    21,600,000 FRAC");
    println!("  Supply reduction:    21.6%");
    println!();
    
    println!("Year 5:");
    println!("  Cumulative burns:    36,000,000 FRAC");
    println!("  Supply reduction:    36%");
    println!("  Remaining supply:    64,000,000 FRAC");
    println!();
    
    println!("📈 With growing demand + shrinking supply = exponential appreciation!");
    println!();

    // ============================================================
    // CALL TO ACTION
    // ============================================================
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  🚀 KEY TAKEAWAYS                                        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    println!("✅ Early adopters earn 10-20x more (epoch multipliers)");
    println!("✅ First 1000 get 2x rewards FOREVER (genesis NFT)");
    println!("✅ Staking adds up to 2x boost (ve_power system)");
    println!("✅ Vesting multiplies earnings 1.5x to 5x");
    println!("✅ Protocol burns tokens constantly (deflationary)");
    println!("✅ Buybacks reduce supply permanently");
    println!();
    println!("💎 Combined advantage for early believers: 50-100x vs late joiners!");
    println!();
    println!("⏰ The best time to join: RIGHT NOW (before genesis NFTs run out!)");
    println!();
}

fn create_demo_proof(task_id: &str) -> CompletedProof {
    CompletedProof {
        task_id: task_id.to_string(),
        aggregated_proof: vec![0u8; 1024], // Large proof
        phi_efficiency: 1.618, // φ-optimized
        contributors: vec![ProverID("demo".to_string())],
        completion_time: std::time::SystemTime::now(),
    }
}

fn print_stats(tokenomics: &FracTokenomics) {
    let stats = tokenomics.get_stats();
    println!("  Minted:      {} FRAC", stats.total_minted);
    println!("  Burned:      {} FRAC", stats.total_burned);
    println!("  Circulating: {} FRAC", stats.circulating_supply);
    println!("  Genesis NFTs: {}/1000", stats.genesis_provers);
}
