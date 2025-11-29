#!/usr/bin/env node
/**
 * Load Testing Tool for Trustless Proving Server
 * Tests system under realistic production load
 */

const axios = require('axios');

const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';
const DURATION_SECONDS = parseInt(process.env.DURATION) || 60;
const CONCURRENT_REQUESTS = parseInt(process.env.CONCURRENCY) || 10;

const stats = {
  total: 0,
  success: 0,
  failed: 0,
  totalTime: 0,
  minTime: Infinity,
  maxTime: 0,
  errors: {}
};

// Generate random transaction
function randomTx() {
  const randomAddress = () => '0x' + Array(40).fill(0).map(() => 
    Math.floor(Math.random() * 16).toString(16)).join('');
  
  return {
    to: randomAddress(),
    data: '0x',
    value: '0',
    gas_limit: '21000'
  };
}

// Single proof request
async function proveTransaction() {
  const start = Date.now();
  
  try {
    const response = await axios.post(`${SERVER_URL}/api/prove`, randomTx(), {
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    const duration = Date.now() - start;
    
    stats.success++;
    stats.totalTime += duration;
    stats.minTime = Math.min(stats.minTime, duration);
    stats.maxTime = Math.max(stats.maxTime, duration);
    
    // Verify proof size
    if (response.data.proof_size_bytes !== 8192) {
      console.error(`❌ Wrong proof size: ${response.data.proof_size_bytes}`);
    }
    
    return duration;
  } catch (error) {
    stats.failed++;
    const errorType = error.code || error.response?.status || 'unknown';
    stats.errors[errorType] = (stats.errors[errorType] || 0) + 1;
    return null;
  } finally {
    stats.total++;
  }
}

// Worker that continuously sends requests
async function worker(id) {
  const startTime = Date.now();
  const endTime = startTime + (DURATION_SECONDS * 1000);
  
  while (Date.now() < endTime) {
    await proveTransaction();
    
    // Small delay to prevent overwhelming
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

// Progress reporter
function startProgressReport() {
  const startTime = Date.now();
  
  const interval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    const rps = (stats.total / elapsed).toFixed(2);
    const avgTime = stats.success > 0 ? (stats.totalTime / stats.success).toFixed(2) : 0;
    const successRate = stats.total > 0 ? ((stats.success / stats.total) * 100).toFixed(1) : 0;
    
    process.stdout.write(`\r⏱️  ${elapsed}s | ` +
      `📊 ${stats.total} req | ` +
      `✅ ${successRate}% | ` +
      `⚡ ${rps} req/s | ` +
      `⏰ ${avgTime}ms avg`);
  }, 1000);
  
  return interval;
}

// Main
async function main() {
  console.log('🧪 TRUSTLESS LOAD TEST');
  console.log('═══════════════════════════════════');
  console.log(`📍 Server: ${SERVER_URL}`);
  console.log(`⏱️  Duration: ${DURATION_SECONDS}s`);
  console.log(`👥 Concurrency: ${CONCURRENT_REQUESTS}`);
  console.log('');
  
  // Health check
  try {
    await axios.get(`${SERVER_URL}/health`);
    console.log('✅ Server is healthy\n');
  } catch (error) {
    console.error('❌ Server health check failed');
    process.exit(1);
  }
  
  // Start load test
  console.log('🚀 Starting load test...\n');
  
  const progressInterval = startProgressReport();
  const startTime = Date.now();
  
  // Start workers
  const workers = [];
  for (let i = 0; i < CONCURRENT_REQUESTS; i++) {
    workers.push(worker(i));
  }
  
  // Wait for completion
  await Promise.all(workers);
  
  clearInterval(progressInterval);
  const totalTime = (Date.now() - startTime) / 1000;
  
  // Results
  console.log('\n\n═══════════════════════════════════');
  console.log('📊 RESULTS');
  console.log('═══════════════════════════════════');
  console.log(`Total Requests:     ${stats.total}`);
  console.log(`Successful:         ${stats.success} (${((stats.success/stats.total)*100).toFixed(1)}%)`);
  console.log(`Failed:             ${stats.failed}`);
  console.log(`Duration:           ${totalTime.toFixed(2)}s`);
  console.log(`Throughput:         ${(stats.total / totalTime).toFixed(2)} req/s`);
  console.log('');
  console.log('Response Times:');
  console.log(`  Min:              ${stats.minTime}ms`);
  console.log(`  Max:              ${stats.maxTime}ms`);
  console.log(`  Average:          ${(stats.totalTime / stats.success).toFixed(2)}ms`);
  
  if (Object.keys(stats.errors).length > 0) {
    console.log('\nErrors:');
    for (const [type, count] of Object.entries(stats.errors)) {
      console.log(`  ${type}: ${count}`);
    }
  }
  
  console.log('═══════════════════════════════════');
  
  // Pass/fail
  const successRate = (stats.success / stats.total) * 100;
  const avgTime = stats.totalTime / stats.success;
  
  if (successRate < 95) {
    console.log('❌ FAILED: Success rate below 95%');
    process.exit(1);
  }
  
  if (avgTime > 1000) {
    console.log('⚠️  WARNING: Average response time > 1s');
  }
  
  console.log('✅ PASSED: System performing well');
}

main().catch(error => {
  console.error('❌ Load test failed:', error.message);
  process.exit(1);
});
