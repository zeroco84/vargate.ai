/**
 * hardhat.config.js — Vargate blockchain configuration.
 * Supports local Hardhat network (for existing tests) and Sepolia testnet
 * (for Stage 7B Merkle anchoring).
 *
 * Environment variables:
 *   SEPOLIA_RPC_URL        — Alchemy/Infura/public Sepolia RPC endpoint
 *   DEPLOYER_PRIVATE_KEY   — hex private key for the deployer account
 *   ETHERSCAN_API_KEY      — (optional) for contract verification
 */

require("@nomicfoundation/hardhat-toolbox");

// Read from env, with safe fallbacks for local-only usage
const SEPOLIA_RPC_URL      = process.env.SEPOLIA_RPC_URL      || "";
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || "";
const ETHERSCAN_API_KEY    = process.env.ETHERSCAN_API_KEY    || "";

const networks = {
  hardhat: {
    chainId: 31337,
    mining: { auto: true, interval: 0 },
  },
};

// Only add Sepolia if credentials are configured
if (SEPOLIA_RPC_URL && DEPLOYER_PRIVATE_KEY) {
  // Ensure key has 0x prefix for ethers
  const key = DEPLOYER_PRIVATE_KEY.startsWith("0x")
    ? DEPLOYER_PRIVATE_KEY
    : `0x${DEPLOYER_PRIVATE_KEY}`;

  networks.sepolia = {
    url: SEPOLIA_RPC_URL,
    chainId: 11155111,
    accounts: [key],
    // Reasonable gas settings for Sepolia
    gasMultiplier: 1.2,
  };
}

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks,
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
};
