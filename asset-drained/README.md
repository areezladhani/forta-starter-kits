# Asset Drained Bot

## Description

This bot detects if an asset is fully drained from a contract. It monitors ERC20 and native tokens transfers from contracts and raises an alert when a contract, having a non-zero token balance in the recent past (10 mins ago), now has 0.

## Supported Chains

- Ethereum
- Optimism
- BNB Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche

## Alerts

- ASSET-DRAINED
  - Fired when an asset is fully drained from a contract
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata:
    - contract - the contract's address
    - asset - the asset's address
    - txHashes - the hashes of the transactions in which the contract was drained
    - blockNumber - the block number at the time of the contract drain
  - Addresses contain the list of addresses that received the assets from the drained contract

## Test Data

### Ethereum Mainnet

The bot behaviour can be verified by running:

- `npm run block 13499798,13499799` (CREAM exploit).
- `npm run block 15572488,15572489` (WinterMute exploit).

Every block we process the transactions from the previous one so when testing you should provide the exploit block and the next one.
