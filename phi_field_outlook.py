#!/usr/bin/env python3
"""
φ-Field Market Outlook: Current positions and next few weeks projection
"""

import numpy as np
import requests
import pandas as pd
from datetime import datetime, timedelta
import json

# Golden ratio constants
PHI = (1 + np.sqrt(5)) / 2
PHI_SQUARED = PHI * PHI
PHI_CONJUGATE = 1 / PHI

def get_current_market_data(coin_id="bitcoin", days=30):
    """Get recent market data for φ-field analysis"""
    try:
        url = f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart"
        params = {
            "vs_currency": "usd",
            "days": days,
            "interval": "daily"
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        
        prices = data['prices']
        df = pd.DataFrame(prices, columns=['timestamp', 'price'])
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ms')
        df.set_index('timestamp', inplace=True)
        
        return df
        
    except Exception as e:
        print(f"API Error for {coin_id}: {e}")
        return pd.DataFrame()

def calculate_phi_indicators(prices):
    """Calculate current φ-field indicators"""
    if len(prices) < 20:
        return {}
    
    # φ-momentum across multiple timeframes
    phi_windows = [int(PHI**i * 10) for i in range(1, 4)]
    phi_momentum = 0
    
    for i, window in enumerate(phi_windows):
        if len(prices) > window:
            momentum = prices.pct_change(window).fillna(0).iloc[-1]
            phi_momentum += momentum * (PHI ** i)
    phi_momentum = phi_momentum / len(phi_windows)
    
    # φ-reversion levels
    window = min(int(PHI * 20), len(prices))
    rolling_max = prices.rolling(window=window).max().iloc[-1]
    rolling_min = prices.rolling(window=window).min().iloc[-1]
    current_price = prices.iloc[-1]
    
    range_size = rolling_max - rolling_min
    phi_618_resistance = rolling_max - range_size * PHI_CONJUGATE
    phi_382_resistance = rolling_max - range_size * (PHI_CONJUGATE**2)
    phi_618_support = rolling_min + range_size * PHI_CONJUGATE
    phi_382_support = rolling_min + range_size * (PHI_CONJUGATE**2)
    
    # φ-cycle position
    phi_period = int(PHI * PHI * 10)
    cycle_position = (len(prices) % phi_period) / phi_period * 2 * np.pi
    phi_cycle = np.sin(cycle_position * PHI) * np.cos(cycle_position / PHI)
    
    # Rhombus field strength
    phi_reversion = 0
    if current_price < phi_382_resistance:
        phi_reversion += 2.0  # Strong oversold
    elif current_price < phi_618_resistance:
        phi_reversion += 1.0  # Oversold
    elif current_price > phi_618_support:
        phi_reversion -= 1.0  # Overbought
    elif current_price > phi_382_support:
        phi_reversion -= 2.0  # Strong overbought
    
    rhombus_field = (phi_momentum * np.cos(72 * np.pi / 180) + 
                    phi_reversion * np.cos(108 * np.pi / 180) + 
                    phi_cycle * PHI) / 3
    
    return {
        'phi_momentum': phi_momentum,
        'phi_reversion': phi_reversion,
        'phi_cycle': phi_cycle,
        'rhombus_field': rhombus_field,
        'current_price': current_price,
        'phi_618_resistance': phi_618_resistance,
        'phi_382_resistance': phi_382_resistance,
        'phi_618_support': phi_618_support,
        'phi_382_support': phi_382_support,
        'rolling_high': rolling_max,
        'rolling_low': rolling_min
    }

def generate_phi_signal(indicators):
    """Generate φ-field trading signal from current indicators"""
    if not indicators:
        return "NO_SIGNAL", "Insufficient data"
    
    field_strength = indicators['rhombus_field']
    phi_momentum = indicators['phi_momentum']
    phi_reversion = indicators['phi_reversion']
    phi_cycle = indicators['phi_cycle']
    
    # Signal thresholds (same as improved strategy)
    field_threshold = 0.1
    momentum_threshold = 0.05
    
    # φ-field buy conditions
    phi_buy_signal = (
        (field_strength > field_threshold) or
        (phi_momentum > momentum_threshold and phi_cycle > -0.5) or
        (phi_reversion > 0.5)  # Strong oversold
    )
    
    # φ-field sell conditions  
    phi_sell_signal = (
        (field_strength < -field_threshold) or
        (phi_momentum < -momentum_threshold and phi_cycle < 0.5) or
        (phi_reversion < -0.5)  # Strong overbought
    )
    
    if phi_buy_signal:
        confidence = abs(field_strength) + max(0, phi_momentum) + max(0, phi_reversion)
        return "BUY", f"φ-field strength: {confidence:.3f}"
    elif phi_sell_signal:
        confidence = abs(field_strength) + abs(min(0, phi_momentum)) + abs(min(0, phi_reversion))
        return "SELL", f"φ-field strength: {confidence:.3f}"
    else:
        return "HOLD", f"φ-field neutral: {field_strength:.3f}"

def analyze_phi_outlook():
    """Analyze current φ-field outlook for next few weeks"""
    print("🔮 φ-FIELD MARKET OUTLOOK: September 11, 2024")
    print("=" * 60)
    print("Current positions and next few weeks projection")
    print()
    
    coins = [
        ("bitcoin", "Bitcoin", "BTC"),
        ("ethereum", "Ethereum", "ETH"), 
        ("cardano", "Cardano", "ADA")
    ]
    
    current_positions = {
        "bitcoin": {"entry_date": "2025-09-01", "entry_price": 108253},
        "ethereum": {"entry_date": "2025-08-25", "entry_price": 4778},
        "cardano": {"entry_date": "2025-08-25", "entry_price": 0.91}
    }
    
    outlook = {}
    
    for coin_id, name, symbol in coins:
        print(f"📊 {name} ({symbol}) φ-Field Analysis")
        print("-" * 40)
        
        # Get recent data
        market_data = get_current_market_data(coin_id, days=30)
        
        if market_data.empty:
            print(f"❌ Unable to fetch current data for {name}")
            continue
            
        # Calculate φ-field indicators
        indicators = calculate_phi_indicators(market_data['price'])
        
        if not indicators:
            print(f"❌ Insufficient data for {name} analysis")
            continue
        
        # Current position analysis
        position = current_positions.get(coin_id)
        current_price = indicators['current_price']
        
        if position:
            entry_price = position['entry_price']
            current_return = (current_price - entry_price) / entry_price * 100
            days_held = (datetime.now() - datetime.strptime("2025-09-01" if coin_id == "bitcoin" else "2025-08-25", "%Y-%m-%d")).days
            
            print(f"📍 CURRENT POSITION: LONG since {position['entry_date']}")
            print(f"   Entry: ${entry_price:,.2f} → Current: ${current_price:,.2f}")
            print(f"   Unrealized P&L: {current_return:+.2f}% ({days_held} days)")
        
        # φ-field technical analysis
        print(f"\n🔬 φ-Field Technical Analysis:")
        print(f"   φ-Momentum: {indicators['phi_momentum']:+.3f}")
        print(f"   φ-Reversion: {indicators['phi_reversion']:+.3f}")
        print(f"   φ-Cycle Position: {indicators['phi_cycle']:+.3f}")
        print(f"   Rhombus Field Strength: {indicators['rhombus_field']:+.3f}")
        
        # Key φ-ratio levels
        print(f"\n📏 Golden Ratio Levels:")
        print(f"   Resistance 61.8%: ${indicators['phi_618_resistance']:,.2f}")
        print(f"   Resistance 38.2%: ${indicators['phi_382_resistance']:,.2f}")
        print(f"   Current Price:    ${current_price:,.2f}")
        print(f"   Support 61.8%:    ${indicators['phi_618_support']:,.2f}")
        print(f"   Support 38.2%:    ${indicators['phi_382_support']:,.2f}")
        
        # Generate signal
        signal, reason = generate_phi_signal(indicators)
        
        print(f"\n🎯 φ-Field Signal: {signal}")
        print(f"   Reasoning: {reason}")
        
        # Outlook interpretation
        if signal == "BUY" and position:
            print("💡 Outlook: CONTINUE HOLDING - φ-field remains bullish")
        elif signal == "SELL" and position:
            print("⚠️  Outlook: CONSIDER TAKING PROFITS - φ-field shows weakness")
        elif signal == "HOLD":
            if position:
                print("⏳ Outlook: MAINTAIN POSITION - φ-field consolidating")
            else:
                print("⏳ Outlook: WAIT FOR CLEARER SIGNAL - φ-field neutral")
        elif signal == "BUY" and not position:
            print("🚀 Outlook: NEW ENTRY OPPORTUNITY - φ-field turning bullish")
        
        # Next few weeks projection
        print(f"\n📈 Next 2-3 Weeks Projection:")
        
        if indicators['phi_cycle'] > 0 and indicators['phi_momentum'] > 0:
            print("   🟢 BULLISH BIAS - φ-cycle and momentum aligned upward")
        elif indicators['phi_cycle'] < 0 and indicators['phi_momentum'] < 0:
            print("   🔴 BEARISH BIAS - φ-cycle and momentum aligned downward")  
        else:
            print("   🟡 MIXED SIGNALS - φ-cycle and momentum diverging")
        
        if abs(indicators['phi_reversion']) > 1.0:
            if indicators['phi_reversion'] > 0:
                print("   📊 Near oversold φ-levels - potential bounce expected")
            else:
                print("   📊 Near overbought φ-levels - potential pullback expected")
        
        outlook[coin_id] = {
            'signal': signal,
            'current_price': current_price,
            'indicators': indicators,
            'position': position
        }
        
        print()
    
    # Overall portfolio outlook
    print("🎯 OVERALL φ-FIELD PORTFOLIO OUTLOOK")
    print("=" * 50)
    
    signals = [outlook[coin]['signal'] for coin in outlook.keys()]
    buy_signals = signals.count('BUY')
    sell_signals = signals.count('SELL')
    hold_signals = signals.count('HOLD')
    
    print(f"📊 Signal Distribution:")
    print(f"   BUY signals: {buy_signals}")
    print(f"   SELL signals: {sell_signals}")
    print(f"   HOLD signals: {hold_signals}")
    
    if buy_signals > sell_signals:
        print("\n🚀 PORTFOLIO BIAS: BULLISH")
        print("   φ-field mathematics favor continued upward momentum")
    elif sell_signals > buy_signals:
        print("\n📉 PORTFOLIO BIAS: BEARISH") 
        print("   φ-field mathematics suggest taking profits/reducing risk")
    else:
        print("\n⚖️ PORTFOLIO BIAS: NEUTRAL")
        print("   φ-field mathematics suggest patience and selective action")
    
    # φ-field cycle analysis for timing
    avg_cycle = np.mean([outlook[coin]['indicators']['phi_cycle'] for coin in outlook.keys()])
    
    print(f"\n🌙 φ-Field Cycle Timing (φ-cycle: {avg_cycle:.3f}):")
    if avg_cycle > 0.5:
        print("   Peak phase - optimal for profit-taking")
    elif avg_cycle < -0.5:
        print("   Trough phase - optimal for accumulation")
    else:
        print("   Transition phase - mixed opportunities")
    
    print(f"\n⏰ Optimal Action Timeline:")
    print(f"   This week: Monitor φ-field strength changes")
    print(f"   Next week: Key φ-ratio levels will be tested") 
    print(f"   Week 3: φ-cycle transition expected - major moves likely")
    
    return outlook

if __name__ == "__main__":
    outlook = analyze_phi_outlook()
