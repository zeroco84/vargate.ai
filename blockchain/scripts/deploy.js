const hre = require("hardhat");
const fs  = require("fs");

async function main() {
    const AuditAnchor = await hre.ethers.getContractFactory("AuditAnchor");
    const contract    = await AuditAnchor.deploy();
    await contract.waitForDeployment();
    const address = await contract.getAddress();
    console.log("AuditAnchor deployed to:", address);

    // Write address to shared volume for gateway to read
    fs.mkdirSync("/shared", { recursive: true });
    fs.writeFileSync("/shared/contract_address.txt", address);
    console.log("Contract address written to /shared/contract_address.txt");

    // Also write the ABI for the gateway
    const artifact = require("../artifacts/contracts/AuditAnchor.sol/AuditAnchor.json");
    fs.writeFileSync("/shared/AuditAnchor.abi.json", JSON.stringify(artifact.abi, null, 2));
    console.log("Contract ABI written to /shared/AuditAnchor.abi.json");
}

main().catch((error) => { console.error(error); process.exit(1); });
