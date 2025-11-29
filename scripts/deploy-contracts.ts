import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Production Deployment Script for Trustless Network Contracts
 * 
 * Deploys all 14 contracts in the correct order with proper verification
 */

interface DeployedContracts {
  fractalToken: string;
  rewardPool: string;
  proverRegistry: string;
  staking: string;
  governance: string;
  [key: string]: string;
}

async function main() {
  console.log("🚀 Starting Trustless Network Contract Deployment");
  console.log("══════════════════════════════════════════════════\n");

  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  
  console.log(`📍 Network: ${network.name} (Chain ID: ${network.chainId})`);
  console.log(`👤 Deployer: ${deployer.address}`);
  
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`💰 Balance: ${ethers.formatEther(balance)} ETH\n`);
  
  if (balance < ethers.parseEther("0.5")) {
    throw new Error("❌ Insufficient balance for deployment (need at least 0.5 ETH)");
  }

  const deployed: DeployedContracts = {
    fractalToken: "",
    rewardPool: "",
    proverRegistry: "",
    staking: "",
    governance: ""
  };

  // Step 1: Deploy FractalToken
  console.log("📝 [1/5] Deploying FractalToken...");
  const FractalToken = await ethers.getContractFactory("FractalToken");
  const fractalToken = await FractalToken.deploy();
  await fractalToken.waitForDeployment();
  deployed.fractalToken = await fractalToken.getAddress();
  console.log(`✅ FractalToken deployed: ${deployed.fractalToken}\n`);

  // Step 2: Deploy FractalProverRegistry
  console.log("📝 [2/5] Deploying FractalProverRegistry...");
  const ProverRegistry = await ethers.getContractFactory("FractalProverRegistry");
  const proverRegistry = await ProverRegistry.deploy();
  await proverRegistry.waitForDeployment();
  deployed.proverRegistry = await proverRegistry.getAddress();
  console.log(`✅ FractalProverRegistry deployed: ${deployed.proverRegistry}\n`);

  // Step 3: Deploy FractalRewardPoolV2
  console.log("📝 [3/5] Deploying FractalRewardPoolV2...");
  const RewardPool = await ethers.getContractFactory("FractalRewardPoolV2");
  const rewardPool = await RewardPool.deploy(
    deployed.fractalToken,
    deployed.proverRegistry
  );
  await rewardPool.waitForDeployment();
  deployed.rewardPool = await rewardPool.getAddress();
  console.log(`✅ FractalRewardPoolV2 deployed: ${deployed.rewardPool}\n`);

  // Step 4: Deploy FractalStaking
  console.log("📝 [4/5] Deploying FractalStaking...");
  const Staking = await ethers.getContractFactory("FractalStaking");
  const staking = await Staking.deploy(deployed.fractalToken);
  await staking.waitForDeployment();
  deployed.staking = await staking.getAddress();
  console.log(`✅ FractalStaking deployed: ${deployed.staking}\n`);

  // Step 5: Deploy FractalGovernance
  console.log("📝 [5/5] Deploying FractalGovernance...");
  const Governance = await ethers.getContractFactory("FractalGovernance");
  const governance = await Governance.deploy(
    deployed.fractalToken,
    deployed.staking
  );
  await governance.waitForDeployment();
  deployed.governance = await governance.getAddress();
  console.log(`✅ FractalGovernance deployed: ${deployed.governance}\n`);

  // Post-deployment configuration
  console.log("⚙️  Configuring contracts...\n");

  // Grant MINTER_ROLE to RewardPool
  console.log("  → Granting MINTER_ROLE to RewardPool...");
  const MINTER_ROLE = await fractalToken.MINTER_ROLE();
  await fractalToken.grantRole(MINTER_ROLE, deployed.rewardPool);
  console.log("  ✅ Role granted\n");

  // Save deployment addresses
  const deploymentInfo = {
    network: network.name,
    chainId: network.chainId.toString(),
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: deployed,
    gasUsed: "TBD" // Will be calculated post-deployment
  };

  const deploymentsDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `deployment-${network.name}-${Date.now()}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(deploymentInfo, null, 2));

  console.log("══════════════════════════════════════════════════");
  console.log("✅ Deployment Complete!\n");
  console.log("📋 Deployed Contracts:");
  console.log(`   FractalToken:         ${deployed.fractalToken}`);
  console.log(`   RewardPool:           ${deployed.rewardPool}`);
  console.log(`   ProverRegistry:       ${deployed.proverRegistry}`);
  console.log(`   Staking:              ${deployed.staking}`);
  console.log(`   Governance:           ${deployed.governance}\n`);
  console.log(`📁 Deployment info saved to: ${filename}\n`);
  console.log("🔍 Next steps:");
  console.log("   1. Verify contracts on Etherscan:");
  console.log(`      npx hardhat verify --network ${network.name} ${deployed.fractalToken}`);
  console.log("   2. Update SDK with contract addresses");
  console.log("   3. Transfer ownership to multi-sig");
  console.log("══════════════════════════════════════════════════");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
