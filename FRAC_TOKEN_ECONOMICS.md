# FRAC Token Economics

**FRAC: The Economic Engine of the Fractal Proving Network**

---

## 🎯 Overview

FRAC is the native utility token that powers the entire Trustless Fractal Proving Network. It creates a decentralized marketplace where users pay for ZK proofs and node operators earn rewards for generating them.

---

## 💰 Token Utility

### 1. **Pay for Proving Services** 💳

Users spend FRAC to access the fractal proving network:

```typescript
// SDK integration
const proof = await Trustless.prove(transaction, {
  payment: {
    amount: 0.01,      // FRAC tokens
    currency: 'FRAC'
  }
});
```

**What users pay for:**
- ✅ Transaction ZODA proofs (security analysis)
- ✅ WARP accumulation (proof compression)
- ✅ Security vulnerability scanning
- ✅ Premium features (priority proving, faster response)
- ✅ Atomic bundle creation

**Pricing tiers:**
- **Basic proof:** 0.01 FRAC (~$0.001 at $0.10/FRAC)
- **Security analysis:** 0.005 FRAC
- **Priority proving:** 0.02 FRAC (2x speed)
- **Enterprise:** Volume discounts (bulk purchases)

---

### 2. **Earn by Running Prover Nodes** 🖥️

Node operators earn FRAC by contributing computational resources:

```bash
# Start a fractal prover node
./production_fractal_prover --earn-frac --stake 1000

# Earnings breakdown per proof:
Base reward:     0.008 FRAC
φ-Position bonus: +20% (if optimally positioned)
Speed bonus:     +10% (if <50ms proving time)
Uptime bonus:    +5% (if >99% uptime)
─────────────────────────────────────────────
Total potential: 0.0108 FRAC per proof
```

**Earning factors:**
- **φ-Coordinates:** Better positioning = higher rewards
- **Performance:** Faster proving = bonus multiplier
- **Uptime:** Reliability = steady income
- **Network level:** Root nodes earn more for aggregation

**Example earnings:**
```
Single node (1000 proofs/day):
├── Base: 8 FRAC/day
├── Bonuses: +2.8 FRAC/day
└── Total: ~10.8 FRAC/day = 324 FRAC/month

10 nodes (optimal φ-cluster):
├── Combined: 108 FRAC/day
├── Cluster bonus: +15% (φ-synergy)
└── Total: ~124 FRAC/day = 3,720 FRAC/month
```

---

### 3. **Stake for Network Participation** 🔒

Staking FRAC provides network security and governance rights:

```
Minimum Stake: 1,000 FRAC
├── Become validator node
├── Earn staking rewards: 5% APY
├── Priority task allocation
├── Governance voting power
└── Slash protection pool
```

**Staking tiers:**

| Tier | Stake Amount | APY | Priority | Vote Weight |
|------|--------------|-----|----------|-------------|
| **Bronze** | 1,000 FRAC | 5% | Normal | 1x |
| **Silver** | 10,000 FRAC | 6% | High | 5x |
| **Gold** | 100,000 FRAC | 7% | Premium | 25x |
| **Platinum** | 1,000,000 FRAC | 8% | Ultra | 100x |

**Staking benefits:**
- ✅ Higher task priority (get more proofs to generate)
- ✅ Vote on protocol parameters
- ✅ Earnings multiplier (up to 1.5x base rate)
- ✅ Reduced slashing risk
- ✅ Access to premium features

**Lock periods:**
- **Flexible:** Unstake anytime (3% penalty)
- **30 days:** +0.5% APY bonus
- **90 days:** +1% APY bonus
- **1 year:** +2% APY bonus

---

### 4. **Governance** 🗳️

FRAC holders vote on network parameters and upgrades:

**Voting power:** 1 FRAC = 1 vote (+ staking multipliers)

**Governance decisions:**
```
Protocol Parameters:
├── Fee structure (currently 2% protocol fee)
├── WARP accumulation thresholds (10x, 100x, 1000x)
├── φ-optimization parameters
├── Node reward distribution
└── Slashing conditions

Network Upgrades:
├── New proof algorithms
├── Security enhancements
├── Integration proposals (L2s, zkEVMs)
├── Treasury spending
└── Partnership approvals

Treasury Allocation:
├── Development grants
├── Security audits
├── Marketing initiatives
├── Community rewards
└── Bug bounties
```

**Voting process:**
1. Proposal submitted (requires 10,000 FRAC stake)
2. 7-day discussion period
3. 7-day voting period
4. Execution if >50% approval + quorum

---

### 5. **Network Fees & Distribution** ⚡

**Fee flow:**
```
User pays: 0.01 FRAC per proof
│
├─→ 2% Protocol fee (0.0002 FRAC)
│   └─→ Treasury (DAO-controlled)
│
└─→ 98% Node rewards (0.0098 FRAC)
    ├─→ 70% Leaf nodes (0.00686 FRAC) - Actual proving
    ├─→ 20% Cluster aggregators (0.00196 FRAC) - WARP accumulation
    └─→ 10% Root nodes (0.00098 FRAC) - Final submission
```

**Fee adjustments:**
- Governance can vote to change protocol fee (1-5% range)
- Node distribution can be rebalanced based on network needs
- Dynamic pricing during high demand

---

## 📊 Tokenomics

### **Supply Distribution:**

```
Total Supply: 100,000,000 FRAC (fixed, no inflation)

Distribution:
├── 40,000,000 FRAC (40%) - Node Mining Rewards
│   └── Released over 10 years via proving rewards
│
├── 25,000,000 FRAC (25%) - Team & Advisors
│   └── 4-year linear vesting, 1-year cliff
│
├── 20,000,000 FRAC (20%) - Community Treasury
│   └── DAO-controlled, grants & ecosystem growth
│
├── 10,000,000 FRAC (10%) - Early Adopters & Incentives
│   └── First 1000 nodes, airdrops, bug bounties
│
└── 5,000,000 FRAC (5%) - Initial Liquidity
    └── DEX liquidity pools (Uniswap, etc.)
```

### **Release Schedule:**

| Year | Mining Rewards | Circulating Supply | % of Total |
|------|----------------|-------------------|------------|
| **Year 1** | 8,000,000 | 23,000,000 | 23% |
| **Year 2** | 6,000,000 | 35,500,000 | 35.5% |
| **Year 3** | 5,000,000 | 46,750,000 | 46.75% |
| **Year 4** | 4,000,000 | 57,000,000 | 57% |
| **Year 5** | 3,500,000 | 66,500,000 | 66.5% |
| **Year 10** | 1,000,000 | 95,000,000 | 95% |

*Team tokens vest linearly over Years 1-4*

---

## 🔥 Deflationary Mechanisms

### **1. Transaction Burn (0.5%)**
```
Every proof payment:
├── User pays: 0.01 FRAC
├── Burned: 0.00005 FRAC (0.5%)
└── Distributed: 0.00995 FRAC

At 1M proofs/day: 500 FRAC burned/day = 182,500 FRAC/year
```

### **2. Slashing**
```
Malicious nodes lose stake:
├── Invalid proof: 10% stake slashed
├── Downtime >24h: 1% stake slashed
├── Byzantine behavior: 50% stake slashed

Slashed tokens: 50% burned, 50% to treasury
```

### **3. Premium Feature Burn**
```
Priority proving fees:
├── 50% to node operators
└── 50% burned

Creates additional deflationary pressure
```

**Net effect:** After Year 3, supply becomes deflationary if >365K proofs/day

---

## 💡 Real-World Use Cases

### **Use Case 1: DeFi Protocol**

**Uniswap V4 Integration**
```
Demand: 1,000,000 proofs/day (security for all swaps)
Cost: 10,000 FRAC/day
Annual: 3.65M FRAC

Creates constant buying pressure
Provers earn: 9,800 FRAC/day distributed across network
```

### **Use Case 2: Wallet Provider**

**MetaMask Integration**
```
Users: 10 million active
Average: 10 transactions/month/user
Total: 100M proofs/month = 3.3M proofs/day

Cost: 33,000 FRAC/day
MetaMask could:
├── Pass cost to users ($0.001/tx)
├── Subsidize (attract users)
└── Offer premium (ad-free + proofs)
```

### **Use Case 3: Professional Node Operator**

**Small Operation (10 nodes)**
```
Hardware: $5,000 investment
Stake: 10,000 FRAC ($1,000 at $0.10)

Monthly earnings:
├── Proving rewards: 3,240 FRAC
├── Staking yield: 50 FRAC (6% APY)
├── φ-position bonus: +486 FRAC
└── Total: 3,776 FRAC/month ($378)

ROI: ~6 months at current prices
```

**Large Operation (100 nodes)**
```
Hardware: $50,000 investment
Stake: 100,000 FRAC ($10,000)

Monthly earnings:
├── Proving rewards: 32,400 FRAC
├── Staking yield: 583 FRAC (7% APY)
├── Cluster synergy: +4,860 FRAC
└── Total: 37,843 FRAC/month ($3,784)

ROI: ~1 year, then pure profit
```

---

## 📈 Growth Projections

### **Phase 1: Launch (Months 1-6)**
```
Network State:
├── 100 active nodes
├── 10,000 proofs/day
├── 50 unique users
└── Price: $0.01 - $0.10/FRAC

Market Cap: $1M - $10M
Daily Volume: $1K - $10K
```

### **Phase 2: Adoption (Months 6-18)**
```
Network State:
├── 1,000 active nodes
├── 100,000 proofs/day
├── 10,000 unique users
├── 5 DeFi integrations
└── Price: $0.10 - $1.00/FRAC

Market Cap: $10M - $100M
Daily Volume: $100K - $1M
```

### **Phase 3: Scale (Months 18+)**
```
Network State:
├── 10,000+ active nodes
├── 1,000,000+ proofs/day
├── 100,000+ unique users
├── 20+ protocol integrations
├── L2 partnerships
└── Price: $1.00 - $10.00/FRAC

Market Cap: $100M - $1B
Daily Volume: $5M - $50M
```

---

## 🎯 Value Accrual

**Why FRAC Price Increases:**

### **1. Network Effects**
```
More Users → More Proofs → More FRAC Demand
     ↓
Higher Price → More Nodes Join → Better Service
     ↓
Better Service → More Users → MORE DEMAND
```

### **2. Staking Lock-Up**
```
At 50% staking rate:
├── 50M FRAC locked in staking
├── Only 50M circulating
└── Reduced supply = Price pressure ↑
```

### **3. Burn Rate**
```
At 1M proofs/day:
├── 500 FRAC burned/day
├── 182,500 FRAC/year burned
└── After 10 years: ~1.8M FRAC removed

Becomes deflationary after Year 3
```

### **4. Required Utility**
```
Can't use network without FRAC:
├── Users must buy to get proofs
├── Nodes must stake to participate
└── Constant demand from both sides
```

---

## 🔒 Security & Safeguards

### **Anti-Manipulation:**
- Max 5% of supply in any single wallet (governance limit)
- Timelocks on large transfers (>100K FRAC)
- Gradual vesting prevents dumps

### **Economic Security:**
- Slashing ensures honest behavior
- Staking creates skin-in-the-game
- φ-optimization prevents centralization

### **Governance Safety:**
- 7-day voting period prevents rushed decisions
- Quorum requirements (20% of staked supply)
- Emergency pause function (requires 80% vote)

---

## 🚀 Launch Strategy

### **Pre-Launch:**
```
✅ Whitepaper published
✅ Smart contracts audited (2 firms)
✅ Testnet live (3 months)
✅ Community building (Discord, Twitter)
```

### **Launch (Month 0):**
```
├── Token Generation Event (TGE)
├── Initial DEX offering (5M FRAC)
├── Airdrop to early testers (500K FRAC)
└── Bootstrap 100 genesis nodes
```

### **Post-Launch (Months 1-3):**
```
├── CEX listings (target: Binance, Coinbase)
├── DeFi integrations (Uniswap, Aave)
├── Node operator onboarding (1000 target)
└── SDK partnerships (wallets, protocols)
```

---

## 💼 Comparable Projects

| Project | Token | Market Cap | Use Case | Similarity |
|---------|-------|------------|----------|------------|
| **Chainlink** | LINK | $7B | Oracle network | Decentralized service, node rewards |
| **The Graph** | GRT | $1.5B | Indexing | Query marketplace, staking model |
| **Filecoin** | FIL | $2B | Storage | Proof generation, node earnings |
| **Render** | RNDR | $2B | GPU compute | Resource marketplace, fractional |
| **FRAC** | FRAC | TBD | ZK Proving | **Combining all: service + staking + marketplace** |

**FRAC positioning:** Only decentralized ZK proving network with fractal optimization

---

## ✅ Summary

**FRAC is essential because:**

1. ✅ **Users need it** to access proving services
2. ✅ **Nodes need it** to participate and earn
3. ✅ **Network needs it** for security (staking)
4. ✅ **Governance needs it** for decentralization
5. ✅ **Economics need it** for value distribution

**It's not just a token - it's the operating system of trustless ZK proving.**

---

## 📞 Resources

- **Website:** trustless.network
- **Docs:** docs.trustless.network
- **Github:** github.com/trustless-network
- **Discord:** discord.gg/trustless
- **Twitter:** @TrustlessZK

**For node operators:** operator.trustless.network  
**For developers:** sdk.trustless.network  
**For investors:** investor.trustless.network

---

*This is not financial advice. Token economics subject to governance votes and market conditions.*
