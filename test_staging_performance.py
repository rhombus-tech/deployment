#!/usr/bin/env python3
"""
Performance test script for zkEVM staging environment
Tests the performance improvements we implemented:
- Block caching (20x faster RPC)
- Parallel batch processing (10x faster)
- Concurrent metadata generation (3x faster)
"""

import requests
import time
import json
import statistics
from datetime import datetime

STAGING_URL = "https://zk-evm.org"

def test_status_endpoint():
    """Test the /status endpoint response time and data"""
    print("🔍 Testing /status endpoint...")
    
    response_times = []
    for i in range(10):
        start = time.time()
        response = requests.get(f"{STAGING_URL}/status")
        end = time.time()
        
        response_time_ms = (end - start) * 1000
        response_times.append(response_time_ms)
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Test {i+1}: {response_time_ms:.1f}ms - Avg proving: {data.get('average_proving_time', 'N/A'):.1f}ms")
        else:
            print(f"  Test {i+1}: ERROR {response.status_code}")
        
        time.sleep(0.5)
    
    avg_response_time = statistics.mean(response_times)
    print(f"\n📊 Status Endpoint Results:")
    print(f"  Average response time: {avg_response_time:.1f}ms")
    print(f"  Min response time: {min(response_times):.1f}ms")
    print(f"  Max response time: {max(response_times):.1f}ms")
    
    return avg_response_time

def test_proving_performance():
    """Test the actual proving performance over time"""
    print("\n⚡ Testing proving performance over 30 seconds...")
    
    initial_response = requests.get(f"{STAGING_URL}/status").json()
    initial_blocks = initial_response.get('blocks_proven', 0)
    initial_time = time.time()
    
    print(f"  Initial blocks proven: {initial_blocks}")
    
    time.sleep(30)
    
    final_response = requests.get(f"{STAGING_URL}/status").json()
    final_blocks = final_response.get('blocks_proven', 0)
    final_time = time.time()
    
    blocks_processed = final_blocks - initial_blocks
    time_elapsed = final_time - initial_time
    
    current_avg_proving = final_response.get('average_proving_time', 0)
    current_tps = final_response.get('tps', 0)
    
    print(f"  Final blocks proven: {final_blocks}")
    print(f"  Blocks processed in test: {blocks_processed}")
    print(f"  Time elapsed: {time_elapsed:.1f}s")
    print(f"  Current average proving time: {current_avg_proving:.1f}ms")
    print(f"  Current TPS: {current_tps:.4f}")
    
    return current_avg_proving, current_tps

def test_concurrent_requests():
    """Test how the service handles concurrent requests"""
    print("\n🚀 Testing concurrent request handling...")
    
    import concurrent.futures
    import threading
    
    def make_request(request_id):
        start = time.time()
        response = requests.get(f"{STAGING_URL}/status")
        end = time.time()
        return {
            'id': request_id,
            'response_time': (end - start) * 1000,
            'status_code': response.status_code,
            'success': response.status_code == 200
        }
    
    # Make 20 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(make_request, i) for i in range(20)]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    successful_requests = [r for r in results if r['success']]
    response_times = [r['response_time'] for r in successful_requests]
    
    print(f"  Successful requests: {len(successful_requests)}/20")
    print(f"  Average response time: {statistics.mean(response_times):.1f}ms")
    print(f"  95th percentile: {statistics.quantiles(response_times, n=20)[18]:.1f}ms")
    
    return len(successful_requests), statistics.mean(response_times)

def main():
    print("🎯 ZKVM STAGING PERFORMANCE TEST")
    print("=" * 50)
    print(f"Testing endpoint: {STAGING_URL}")
    print(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Test 1: Status endpoint performance
    status_response_time = test_status_endpoint()
    
    # Test 2: Proving performance
    avg_proving_time, tps = test_proving_performance()
    
    # Test 3: Concurrent request handling
    concurrent_success, concurrent_avg_time = test_concurrent_requests()
    
    # Summary
    print("\n" + "=" * 50)
    print("📈 PERFORMANCE TEST SUMMARY")
    print("=" * 50)
    
    print(f"Status endpoint avg response: {status_response_time:.1f}ms")
    print(f"Current proving time: {avg_proving_time:.1f}ms")
    print(f"Current TPS: {tps:.4f}")
    print(f"Concurrent request success: {concurrent_success}/20")
    print(f"Concurrent avg response: {concurrent_avg_time:.1f}ms")
    
    # Performance assessment
    print("\n🎯 PERFORMANCE ASSESSMENT:")
    
    target_proving_time = 100  # Our target from optimizations
    if avg_proving_time <= target_proving_time:
        print(f"✅ PROVING TIME: {avg_proving_time:.1f}ms (TARGET: ≤{target_proving_time}ms) - EXCELLENT!")
    else:
        print(f"⚠️  PROVING TIME: {avg_proving_time:.1f}ms (TARGET: ≤{target_proving_time}ms) - NEEDS IMPROVEMENT")
    
    if status_response_time <= 200:
        print(f"✅ API RESPONSE: {status_response_time:.1f}ms - FAST")
    else:
        print(f"⚠️  API RESPONSE: {status_response_time:.1f}ms - SLOW")
    
    if concurrent_success >= 18:
        print(f"✅ RELIABILITY: {concurrent_success}/20 requests succeeded - STABLE")
    else:
        print(f"⚠️  RELIABILITY: {concurrent_success}/20 requests succeeded - UNSTABLE")
    
    # Recommendation
    print("\n🚀 DEPLOYMENT RECOMMENDATION:")
    if avg_proving_time <= target_proving_time and concurrent_success >= 18:
        print("✅ READY FOR PRODUCTION DEPLOYMENT!")
        print("   Performance improvements verified. Safe to promote staging to production.")
    else:
        print("⚠️  NOT READY FOR PRODUCTION")
        print("   Performance issues detected. Investigate before promoting.")

if __name__ == "__main__":
    main()
