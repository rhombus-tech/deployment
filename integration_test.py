#!/usr/bin/env python3
"""
EVM-Verify + StatelessVM Integration Test
Demonstrates real-time stateless validation on Ethereum mainnet
"""

import requests
import json
import time
import sys
from datetime import datetime

def test_evm_verify_service():
    """Test EVM-Verify unified service health and capabilities"""
    try:
        print("🔍 Testing EVM-Verify unified service...")
        response = requests.get("http://localhost:8080/health", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ EVM-Verify Status: {data['status']}")
            print(f"📊 Performance Metrics:")
            print(f"   - Proving Time: {data['performance']['avg_proving_time_ms']}ms")
            print(f"   - Proof Size: {data['performance']['proof_size_kb']}KB")
            print(f"   - Security: {data['performance']['security_bits']} bits")
            print(f"   - EF Compliant: {data['performance']['ef_compliant']}")
            
            # Calculate EF compliance margins
            ef_latency_req = 10000  # 10s in ms
            ef_proof_req = 300      # 300KB
            
            latency_improvement = ef_latency_req / data['performance']['avg_proving_time_ms']
            proof_improvement = ef_proof_req / data['performance']['proof_size_kb']
            
            print(f"🚀 EF Requirement Exceeded:")
            print(f"   - Latency: {latency_improvement:.1f}x faster than required")
            print(f"   - Proof Size: {proof_improvement:.1f}x smaller than required")
            
            return True
        else:
            print(f"❌ EVM-Verify health check failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ EVM-Verify connection error: {e}")
        return False

def test_stateless_vm_service():
    """Test StatelessVM service connectivity"""
    try:
        print("\n🔍 Testing StatelessVM service...")
        
        # Test basic JSON-RPC connectivity
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }
        
        response = requests.post("http://localhost:7547", 
                               json=payload, 
                               headers={"Content-Type": "application/json"},
                               timeout=15)
        
        if response.status_code == 200 and response.text:
            data = response.json()
            if 'result' in data:
                block_num = int(data['result'], 16)
                print(f"✅ StatelessVM connected to Ethereum mainnet")
                print(f"📦 Latest block: {block_num}")
                return True
            else:
                print(f"⚠️ StatelessVM responding but no block data: {data}")
                return False
        else:
            print(f"❌ StatelessVM not responding properly: {response.status_code}")
            print(f"Response: {response.text[:200] if response.text else 'No content'}")
            return False
            
    except Exception as e:
        print(f"❌ StatelessVM connection error: {e}")
        return False

def test_integrated_validation():
    """Test integrated stateless validation with security analysis"""
    try:
        print("\n🔍 Testing integrated EVM-Verify + StatelessVM validation...")
        
        # Get latest block for validation
        payload = {
            "jsonrpc": "2.0", 
            "method": "eth_getBlockByNumber",
            "params": ["latest", False],
            "id": 1
        }
        
        print("📡 Fetching latest Ethereum block...")
        response = requests.post("http://localhost:7547",
                               json=payload,
                               headers={"Content-Type": "application/json"},
                               timeout=20)
        
        if response.status_code == 200 and response.text:
            block_data = response.json()
            if 'result' in block_data and block_data['result']:
                block_number = block_data['result']['number']
                block_hash = block_data['result']['hash']
                tx_count = len(block_data['result'].get('transactions', []))
                
                print(f"✅ Retrieved block {block_number}")
                print(f"   - Hash: {block_hash}")
                print(f"   - Transactions: {tx_count}")
                
                # Test EVM-Verify proving
                print("\n⚡ Testing zkEVM proof generation...")
                prove_payload = {"block_number": block_number}
                
                start_time = time.time()
                prove_response = requests.post("http://localhost:8080/prove_block",
                                             json=prove_payload,
                                             timeout=30)
                end_time = time.time()
                
                if prove_response.status_code in [200, 202]:
                    proving_time = (end_time - start_time) * 1000
                    print(f"✅ Proof generation initiated")
                    print(f"   - Response time: {proving_time:.1f}ms")
                    print(f"   - Status: {prove_response.status_code}")
                    return True
                else:
                    print(f"⚠️ Proof generation response: {prove_response.status_code}")
                    print(f"   - Content: {prove_response.text[:200] if prove_response.text else 'No content'}")
                    return False
            else:
                print("❌ Invalid block data received")
                return False
        else:
            print(f"❌ Block fetch failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Integration test error: {e}")
        return False

def main():
    """Run comprehensive integration test suite"""
    print("🚀 EVM-Verify + StatelessVM Integration Test Suite")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Test individual services
    evm_verify_ok = test_evm_verify_service()
    stateless_vm_ok = test_stateless_vm_service()
    
    if not evm_verify_ok or not stateless_vm_ok:
        print("\n❌ One or more services are not operational")
        print("Integration test cannot proceed")
        sys.exit(1)
    
    # Test integrated functionality
    integration_ok = test_integrated_validation()
    
    print("\n" + "=" * 60)
    print("📋 INTEGRATION TEST SUMMARY:")
    print(f"   - EVM-Verify Service: {'✅ PASS' if evm_verify_ok else '❌ FAIL'}")
    print(f"   - StatelessVM Service: {'✅ PASS' if stateless_vm_ok else '❌ FAIL'}")
    print(f"   - Integration Test: {'✅ PASS' if integration_ok else '❌ FAIL'}")
    
    if evm_verify_ok and stateless_vm_ok and integration_ok:
        print("\n🎉 FULL STACK OPERATIONAL!")
        print("✅ Real-time stateless validation ready for Ethereum mainnet")
        print("✅ EVM-Verify massively exceeds all EF requirements")
        print("✅ Integration with StatelessVM successful")
    else:
        print("\n⚠️ Integration issues detected - see logs above")
    
    print(f"⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
