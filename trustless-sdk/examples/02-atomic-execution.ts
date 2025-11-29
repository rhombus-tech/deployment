/**
 * Example 2: Atomic Multi-Transaction Execution
 * 
 * Shows how to execute multiple transactions atomically
 * ALL succeed or ALL fail - no partial execution
 */

import { Trustless } from '../src/index';

async function main() {
  console.log('🚀 Trustless SDK - Atomic Execution Example\n');

  // Initialize
  console.log('1️⃣  Initializing...');
  await Trustless.init({
    network: 'mainnet',
    enableSecurity: true,
    debug: false
  });
  console.log('✅ Initialized\n');

  // Create atomic bundle
  console.log('2️⃣  Creating atomic bundle...');
  
  const bundle = {
    transactions: [
      // Transaction 1: Approve token spend
      {
        to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
        data: '0x095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000005f5e100', // approve(spender, amount)
      },
      // Transaction 2: Swap on DEX
      {
        to: '0xDef1C0ded9bec7F1a1670819833240f027b25EfF', // 0x Exchange
        data: '0xd9627aa4...', // swap calldata
      },
      // Transaction 3: Transfer result
      {
        to: '0x6B175474E89094C44Da98b954EedeAC495271d0F', // DAI
        data: '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f0beb0000000000000000000000000000000000000000000000056bc75e2d63100000', // transfer(to, amount)
      }
    ],
    revertOnFailure: true, // ALL or nothing
  };

  console.log(`   Created bundle with ${bundle.transactions.length} transactions\n`);

  // Generate atomic proof
  console.log('3️⃣  Generating atomic proof...');
  const startTime = Date.now();
  
  const atomicProof = await Trustless.atomic(bundle, (event) => {
    if (event.type === 'PROOF_GENERATION') {
      console.log(`   ⚡ Progress: ${event.progress.toFixed(0)}%`);
    }
  });
  
  const provingTime = Date.now() - startTime;
  console.log(`✅ Atomic proof generated in ${provingTime}ms\n`);

  // Check atomic proof details
  console.log('4️⃣  Atomic Proof Details:');
  console.log(`   Bundle Hash: ${atomicProof.bundleHash}`);
  console.log(`   Guaranteed Atomic: ${atomicProof.guaranteedAtomic ? '✅ YES' : '❌ NO'}`);
  console.log(`   Total Gas Estimate: ${atomicProof.totalGasEstimate}`);
  console.log(`   Individual Proofs: ${atomicProof.proofs.length}\n`);

  // Show individual proof scores
  console.log('5️⃣  Individual Transaction Scores:');
  atomicProof.proofs.forEach((proof, i) => {
    console.log(`   TX ${i + 1}: Trustless Score ${proof.trustlessScore}/100`);
    console.log(`        Security: ${proof.security.isSecure ? '✅' : '⚠️ '} ${proof.security.securityScore}/100`);
    console.log(`        Proving Time: ${proof.zkProof.provingTime}ms`);
  });
  console.log();

  // Calculate composite score
  const averageScore = atomicProof.proofs.reduce((sum, p) => sum + p.trustlessScore, 0) / atomicProof.proofs.length;
  console.log(`6️⃣  Bundle Composite Score: ${averageScore.toFixed(1)}/100\n`);

  console.log('🎉 Atomic proof ready!\n');
  console.log('💡 Key Benefits:');
  console.log('   ✅ All transactions execute together or fail together');
  console.log('   ✅ No partial execution possible');
  console.log('   ✅ Math-proven atomicity guarantees');
  console.log('   ✅ Each transaction individually verified for security\n');

  console.log('📤 To submit:');
  console.log('   const receipt = await Trustless.submitAtomic(atomicProof);\n');

  // Cleanup
  await Trustless.cleanup();
}

// Run the example
main().catch(console.error);
