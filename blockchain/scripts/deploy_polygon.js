/**
 * deploy_polygon.js — Deploys MerkleAuditAnchor.sol to Polygon (Amoy testnet or mainnet).
 * Writes deployed address + ABI to /shared/PolygonMerkleAuditAnchor.json.
 *
 * Usage:
 *   npx hardhat run scripts/deploy_polygon.js --network polygon_amoy
 *   npx hardhat run scripts/deploy_polygon.js --network polygon
 *
 * Environment:
 *   POLYGON_PRIVATE_KEY — hex private key for deployer wallet
 */

const hre = require("hardhat");
const fs  = require("fs");

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying MerkleAuditAnchor with account:", deployer.address);

    const balance = await hre.ethers.provider.getBalance(deployer.address);
    console.log("Account balance:", hre.ethers.formatEther(balance), "MATIC/POL");

    if (balance === 0n) {
        console.error("ERROR: Deployer account has zero balance. Fund it first.");
        process.exit(1);
    }

    const networkName = hre.network.name;
    console.log("Network:", networkName);

    const MerkleAuditAnchor = await hre.ethers.getContractFactory("MerkleAuditAnchor");
    const contract = await MerkleAuditAnchor.deploy();
    await contract.waitForDeployment();
    const address = await contract.getAddress();

    console.log("MerkleAuditAnchor deployed to:", address);

    const artifact = require("../artifacts/contracts/MerkleAuditAnchor.sol/MerkleAuditAnchor.json");
    const output = {
        address: address,
        abi: artifact.abi,
        network: networkName,
        deployer: deployer.address,
        deployedAt: new Date().toISOString(),
    };

    const sharedPath = "/shared/PolygonMerkleAuditAnchor.json";
    const localPath = "./PolygonMerkleAuditAnchor-deployed.json";

    try {
        fs.mkdirSync("/shared", { recursive: true });
        fs.writeFileSync(sharedPath, JSON.stringify(output, null, 2));
        console.log(`Contract info written to ${sharedPath}`);
    } catch (err) {
        console.log(`Could not write to ${sharedPath} (not in Docker?), writing locally.`);
    }

    fs.writeFileSync(localPath, JSON.stringify(output, null, 2));
    console.log(`Contract info written to ${localPath}`);

    const explorer = networkName === "polygon"
        ? "https://polygonscan.com"
        : "https://amoy.polygonscan.com";

    console.log("\n── Verify on Explorer ──");
    console.log(`npx hardhat verify --network ${networkName} ${address}`);
    console.log(`\nOr visit: ${explorer}/address/${address}`);
}

main().catch((error) => { console.error(error); process.exit(1); });
