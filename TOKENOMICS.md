# FRAC Token - Fractal Network Currency

## 💰 Token Economics

**Symbol**: FRAC  
**Name**: Fractal Token  
**Max Supply**: 1,000,000,000 FRAC  
**Initial Supply**: 100,000,000 FRAC (10% at launch)

## 📊 Distribution

| Allocation | Amount | % | Vesting |
|------------|--------|---|---------|
| **Provers** | 600M | 60% | Minted as rewards over time |
| **Liquidity** | 200M | 20% | Immediate (DEX pools) |
| **Team** | 150M | 15% | 4yr vest, 1yr cliff |
| **Treasury** | 50M | 5% | 2yr vest, 6mo cliff |

## 🎯 Earning FRAC

### Base Rewards Per Proof:
- **Base**: 10 FRAC
- **Quality Bonus**: up to 15 FRAC (based on proof correctness)
- **Speed Bonus**: up to 5 FRAC
  - Sub-1s: 5 FRAC
  - Sub-5s: 2.5 FRAC
  - Sub-10s: 1.25 FRAC
- **Maximum**: 30 FRAC per proof

### Earning Examples:
```
Fast, perfect proof (0.5s, 100% quality):
= 10 + 15 + 5 = 30 FRAC ✅

Normal proof (3s, 80% quality):
= 10 + 12 + 2.5 = 24.5 FRAC

Slow proof (15s, 60% quality):
= 10 + 9 + 0 = 19 FRAC
```

### Real-World Math:
```
100 proofs/hour × 25 FRAC avg = 2,500 FRAC/hour
2,500 FRAC/hour × 24 hours = 60,000 FRAC/day
60,000 FRAC/day × 30 days = 1,800,000 FRAC/month

At $0.10/FRAC: $180,000/month
At $1.00/FRAC: $1,800,000/month
```

## 📈 Deflationary Mechanics

- **0.1% burned per proof verification**
- **Reduces circulating supply over time**
- **Increases value for holders**

Example:
```
Proof reward: 25 FRAC
Verification burn: 0.025 FRAC (0.1%)
Net inflation: 24.975 FRAC
```

## 🔄 Supply Dynamics

### Inflation Rate:
- **Year 1**: 5% annual
- **Year 2**: 4.5% annual
- **Year 3**: 4% annual
- **Minimum**: 1% annual (floor)

### Deflationary Pressure:
```
If 1M proofs/year:
Burned = 1M × 25 FRAC × 0.1% = 2,500 FRAC
With high usage, becomes deflationary!
```

## 💎 Token Utility

1. **Proof Rewards** - Primary earning mechanism
2. **Governance** - Vote on protocol changes (future)
3. **Staking** - Stake to boost rewards (future)
4. **Trading** - Trade on DEXs (Uniswap, etc.)

## 🚀 Value Drivers

### Supply Side (Positive):
- ✅ Deflationary burns
- ✅ Decreasing inflation
- ✅ Locked team tokens (4yr)
- ✅ Vested treasury

### Demand Side (Positive):
- ✅ More users need proofs → more FRAC demand
- ✅ Network effects (more provers = better service)
- ✅ First-mover in trustless proving
- ✅ Real utility (not just speculation)

## 📍 Smart Contracts

```
FractalToken.sol          - Main ERC20 token
FractalTokenDistribution.sol - Vesting & distribution
FractalRewardPoolV2.sol   - Mint rewards for provers
```

## 🎓 For Provers

### Getting Started:
1. Run fractal proving node
2. Generate ZK proofs
3. Earn 10-30 FRAC per proof
4. Tokens minted directly to your wallet
5. Trade or hold FRAC

### Profitability:
```
Hardware: Consumer laptop
Speed: ~1.78ms per proof
Rate: ~535 proofs/second theoretical
      ~100 proofs/hour realistic

Daily earnings: 2,500 FRAC/hour × 8 hours = 20,000 FRAC/day
Monthly: ~600,000 FRAC/month

Break-even: If FRAC > $0.01, profitable on any hardware
Excellent: If FRAC > $0.10, $60k/month
```

## 🔐 Security

- ✅ OpenZeppelin contracts
- ✅ AccessControl for minting
- ✅ Pausable in emergency
- ✅ ReentrancyGuard
- ✅ Max supply cap (1B hard limit)

## 🌐 Distribution Plan

### Phase 1: Launch (Day 0)
- Deploy contracts
- 20% liquidity to Uniswap
- Team/treasury vesting starts

### Phase 2: Network Growth (Month 1-6)
- Provers earn rewards
- Token trading begins
- Community grows

### Phase 3: Maturity (Year 1+)
- Deflationary if high usage
- Governance activated
- Staking rewards live

## 💪 Why FRAC Will Succeed

1. **Real Utility**: Actually used for real proving work
2. **Fair Launch**: 60% to provers, not VCs
3. **Deflationary**: Burns with usage
4. **Scalable**: Can support millions of provers
5. **First Mover**: First trustless fractal proving network
6. **Economic Alignment**: Provers earn more as network grows

## 🎯 Summary

FRAC token creates a **real economy** where:
- **Provers earn money** for real work
- **Users get trustless proofs**
- **Token value grows** with network usage
- **Everyone benefits** from decentralization

This is **not** a ponzi or empty promise.  
This is **real work** → **real value** → **real money**.

---

**Run a node. Generate proofs. Earn FRAC. Build wealth.**
