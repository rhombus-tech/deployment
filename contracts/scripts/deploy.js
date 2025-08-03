const { ethers } = require("hardhat");

async function main() {
  console.log("🚀 Deploying VerifiedAtomicExecutor...");
  
  // Get the ContractFactory and Signers here.
  const [deployer] = await ethers.getSigners();
  
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  // Deploy VerifiedAtomicExecutor
  const VerifiedAtomicExecutor = await ethers.getContractFactory("VerifiedAtomicExecutor");
  const atomicExecutor = await VerifiedAtomicExecutor.deploy();

  await atomicExecutor.deployed();

  console.log("✅ VerifiedAtomicExecutor deployed to:", atomicExecutor.address);
  
  // Save deployment info
  const deploymentInfo = {
    network: network.name,
    contractAddress: atomicExecutor.address,
    deployer: deployer.address,
    blockNumber: (await ethers.provider.getBlockNumber()).toString(),
    timestamp: new Date().toISOString(),
  };
  
  console.log("\n📋 Deployment Summary:");
  console.log("Network:", deploymentInfo.network);
  console.log("Contract Address:", deploymentInfo.contractAddress);
  console.log("Deployer:", deploymentInfo.deployer);
  console.log("Block Number:", deploymentInfo.blockNumber);
  
  // Save to file for StatelessVM integration
  const fs = require('fs');
  fs.writeFileSync(
    'deployment-info.json',
    JSON.stringify(deploymentInfo, null, 2)
  );
  
  console.log("\n✅ Deployment info saved to deployment-info.json");
  console.log("🔗 Use this address in your StatelessVM configuration");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
