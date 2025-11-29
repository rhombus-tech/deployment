/**
 * Example 1: Basic Usage
 * 
 * Shows the simplest way to use the Trustless SDK
 */

import { Trustless } from '../src/index';

async function main() {
  console.log('🚀 Trustless SDK - Basic Usage Example\n');

  // Step 1: Initialize
  console.log('1️⃣  Initializing...');
  await Trustless.init({
    network: 'mainnet',
    enableSecurity: true,
    debug: true
  });
  console.log('✅ Initialized\n');

  // Step 2: Create a transaction
  console.log('2️⃣  Creating transaction...');
  const transaction = {
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    data: '0x',
    value: 1000000000000000n, // 0.001 ETH
  };
  console.log('Transaction:', transaction, '\n');

  // Step 3: Prove the transaction
  console.log('3️⃣  Generating proof...');
  const startTime = Date.now();
  
  const proof = await Trustless.prove(transaction, (event) => {
    if (event.type === 'SECURITY_ANALYSIS') {
      console.log(`   🔍 Security analysis: ${event.progress.toFixed(0)}%`);
    }
    if (event.type === 'PROOF_GENERATION') {
      console.log(`   ⚡ Proof generation: ${event.progress.toFixed(0)}%`);
    }
  });
  
  const provingTime = Date.now() - startTime;
  console.log(`✅ Proof generated in ${provingTime}ms\n`);

  // Step 4: Check the results
  console.log('4️⃣  Proof Details:');
  console.log(`   Trustless Score: ${proof.trustlessScore}/100`);
  console.log(`   Security: ${proof.security.isSecure ? '✅ Secure' : '⚠️  Issues detected'}`);
  console.log(`   Security Score: ${proof.security.securityScore}/100`);
  console.log(`   Vulnerabilities: ${proof.security.vulnerabilities.length}`);
  console.log(`   Proof Size: ${proof.zkProof.proof.length} bytes`);
  console.log(`   Proving Time: ${proof.zkProof.provingTime}ms\n`);

  // Step 5: Check vulnerabilities (if any)
  if (proof.security.vulnerabilities.length > 0) {
    console.log('⚠️  Detected Vulnerabilities:');
    proof.security.vulnerabilities.forEach((vuln, i) => {
      console.log(`   ${i + 1}. [${vuln.severity}] ${vuln.type}`);
      console.log(`      ${vuln.description}`);
    });
    console.log();
  }

  // Step 6: Get statistics
  const stats = Trustless.getStats();
  console.log('5️⃣  SDK Statistics:');
  console.log(`   Total Proofs: ${stats.totalProofs}`);
  console.log(`   Successful: ${stats.successfulProofs}`);
  console.log(`   Failed: ${stats.failedProofs}`);
  console.log(`   Avg Proving Time: ${stats.averageProvingTime.toFixed(2)}ms`);
  console.log(`   Avg Trustless Score: ${stats.trustlessScore.toFixed(2)}/100\n`);

  console.log('🎉 Example complete!\n');
  console.log('💡 In production, you would call Trustless.submit(proof) to send the transaction.\n');

  // Cleanup
  await Trustless.cleanup();
}

// Run the example
main().catch(console.error);
