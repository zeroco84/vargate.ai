FROM node:20-alpine

RUN apk add --no-cache curl

WORKDIR /app

# Install hardhat and dependencies
COPY package.json ./
RUN npm install

# Copy project files
COPY hardhat.config.js .
COPY contracts/ ./contracts/
COPY scripts/ ./scripts/
COPY entrypoint.sh .

# Compile contracts
RUN npx hardhat compile

# NOTE: Blockchain runs as root because it writes contract addresses to /shared/
# which is consumed by the gateway. Hardhat's ephemeral chain is demo-grade.

EXPOSE 8545

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
