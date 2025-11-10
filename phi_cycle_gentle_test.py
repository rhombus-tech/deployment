#!/usr/bin/env python3
"""
Gentle φ-cycle validation with proper API rate limiting
"""

import requests
import time
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def get_crypto_data_safely(coin_id, days=30):
    """Get crypto data with proper rate limiting"""
    print(f"Fetching {coin_id} data (waiting 3 seconds between requests)...")
    
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart"
        params = {"vs_currency": "usd", "days": days, "interval": "daily"}
        
        # Add delay to respect rate limits
        time.sleep(3)
        
        response = requests.get(url, params=params, timeout=30)
        print(f"Response status for {coin_id}: {response.status_code}")
        
        if response.status_code == 429:
            print(f"Rate limited on {coin_id}, waiting 60 seconds...")
            time.sleep(60)
            response = requests.get(url, params=params, timeout=30)
        
        response.raise_for_status()
        data = response.json()
        
        prices = data['prices']
        df = pd.DataFrame(prices, columns=['timestamp', 'price'])
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
        df.set_index('timestamp', inplace=True)
        
        print(f"✅ Successfully got {len(df)} days of {coin_id} data")
        return df
        
    except Exception as e:
        print(f"❌ Error fetching {coin_id}: {e}")
        return pd.DataFrame()

def calculate_phi_cycle_position(price_data, phi_period=26.2):
    """Calculate current φ-cycle position from price data"""
    if len(price_data) < 10:
        print(f"   Insufficient data: only {len(price_data)} days")
        return None
    
    PHI = (1 + np.sqrt(5)) / 2
    prices = price_data['price'].values
    price_changes = np.diff(prices) / prices[:-1]
    
    print(f"   Analyzing {len(prices)} price points...")
    print(f"   Price range: ${prices.min():.0f} - ${prices.max():.0f}")
    
    # Try different cycle start points
    best_correlation = 0
    best_position = None
    
    for start_offset in range(min(10, len(prices) - 5)):
        phi_values = []
        
        for i in range(start_offset, len(prices)):
            days_from_start = i - start_offset
            cycle_position = (days_from_start % phi_period) / phi_period * 2 * np.pi
            phi_cycle = np.sin(cycle_position * PHI) * np.cos(cycle_position / PHI)
            phi_values.append(phi_cycle)
        
        # Ensure we have enough data points
        if len(phi_values) > len(price_changes):
            phi_values = phi_values[:len(price_changes)]
        elif len(phi_values) < len(price_changes):
            continue
            
        if len(phi_values) >= 5 and len(price_changes) >= 5:
            try:
                correlation = abs(np.corrcoef(phi_values, price_changes)[0, 1])
                
                if not np.isnan(correlation) and correlation > best_correlation:
                    best_correlation = correlation
                    
                    # Calculate current position
                    current_day = len(prices) - 1
                    days_from_start = current_day - start_offset
                    current_cycle_pos = (days_from_start % phi_period) / phi_period * 2 * np.pi
                    current_phi = np.sin(current_cycle_pos * PHI) * np.cos(current_cycle_pos / PHI)
                    
                    best_position = {
                        'current_phi_value': current_phi,
                        'correlation': correlation,
                        'days_in_cycle': days_from_start % phi_period,
                        'cycle_position_radians': current_cycle_pos,
                        'start_offset': start_offset
                    }
            except Exception as e:
                continue
    
    if best_position:
        print(f"   Best φ-cycle correlation: {best_position['correlation']:.3f}")
    else:
        print(f"   No valid φ-cycle correlation found (tried {min(10, len(prices) - 5)} offsets)")
    
    return best_position

def run_gentle_validation():
    """Run validation with proper API etiquette"""
    print("🧪 GENTLE φ-CYCLE VALIDATION")
    print("=" * 50)
    print("Testing with proper rate limiting...")
    
    results = {}
    
    # Test multiple cryptos with delays
    for coin in ['bitcoin', 'ethereum', 'cardano']:  # Test major cryptos
        print(f"\n📈 Testing {coin.upper()}...")
        
        data = get_crypto_data_safely(coin, days=30)
        if data.empty:
            results[coin] = {'status': 'failed', 'error': 'No data'}
            continue
        
        phi_position = calculate_phi_cycle_position(data)
        if phi_position is None:
            results[coin] = {'status': 'failed', 'error': 'No φ-cycle detected'}
            print(f"   ❌ No φ-cycle pattern detected in {len(data)} days of data")
            continue
        
        print(f"   Current φ-value: {phi_position['current_phi_value']:.3f}")
        print(f"   Correlation strength: {phi_position['correlation']:.3f}")
        print(f"   Days in cycle: {phi_position['days_in_cycle']:.1f}")
        
        # Assess crash probability
        phi_val = phi_position['current_phi_value']
        correlation = phi_position['correlation']
        days_in_cycle = phi_position['days_in_cycle']
        
        # Crash indicators
        approaching_peak = phi_val > 0.5  # Positive φ-value
        strong_correlation = correlation > 0.3
        mid_cycle_timing = 10 < days_in_cycle < 20  # Middle of 26-day cycle
        
        crash_probability = 0
        if approaching_peak:
            crash_probability += 0.3
        if strong_correlation:
            crash_probability += 0.4
        if mid_cycle_timing:
            crash_probability += 0.3
        
        results[coin] = {
            'status': 'success',
            'phi_value': phi_position['current_phi_value'],
            'correlation': phi_position['correlation'],
            'days_in_cycle': phi_position['days_in_cycle'],
            'crash_probability': crash_probability,
            'indicators': {
                'approaching_peak': approaching_peak,
                'strong_correlation': strong_correlation,
                'mid_cycle_timing': mid_cycle_timing
            }
        }
    
    # Overall assessment
    print(f"\n🏆 OVERALL ASSESSMENT")
    print("=" * 50)
    
    successful_tests = [r for r in results.values() if r['status'] == 'success']
    
    if successful_tests:
        avg_crash_prob = np.mean([r['crash_probability'] for r in successful_tests])
        avg_phi = np.mean([r['phi_value'] for r in successful_tests])
        avg_correlation = np.mean([r['correlation'] for r in successful_tests])
        
        print(f"📊 Average φ-value: {avg_phi:.3f}")
        print(f"📊 Average correlation: {avg_correlation:.3f}")
        print(f"📊 Crash probability: {avg_crash_prob:.1%}")
        
        if avg_crash_prob > 0.6:
            print("🚨 HIGH CRASH RISK detected")
        elif avg_crash_prob > 0.4:
            print("⚠️  MODERATE CRASH RISK detected")
        else:
            print("✅ LOW CRASH RISK detected")
            
        # Save results
        with open('/Users/talzisckind/Downloads/deployment/gentle_validation_results.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'results': results,
                'summary': {
                    'avg_crash_probability': avg_crash_prob,
                    'avg_phi_value': avg_phi,
                    'avg_correlation': avg_correlation
                }
            }, f, indent=2, default=str)
        
        return results
    else:
        print("❌ All tests failed - cannot assess crash risk")
        return None

if __name__ == "__main__":
    run_gentle_validation()
