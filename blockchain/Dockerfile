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

EXPOSE 8545

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
