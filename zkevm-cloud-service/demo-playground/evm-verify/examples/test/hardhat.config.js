require("@nomiclabs/hardhat-waffle");
require("@nomiclabs/hardhat-ethers");

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: {
    version: "0.8.17",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    hardhat: {
      forking: {
        // You need to replace this with your own RPC URL for Avalanche mainnet
        url: "https://api.avax.network/ext/bc/C/rpc",
        blockNumber: 21470000 // Use a specific block number for consistent testing
      },
      chainId: 43114, // Avalanche C-Chain
      accounts: {
        mnemonic: "test test test test test test test test test test test junk", // Default hardhat mnemonic
        accountsBalance: "10000000000000000000000" // 10000 AVAX
      }
    }
  },
  mocha: {
    timeout: 100000
  }
};
