# Flashbots Transactions Detection Bot

## Description

This bot detects flashbot transactions

## Supported Chains

- Ethereum

## Alerts

- FLASHBOTS-TRANSACTIONS
  - Fired when the Flashbots API flags a transaction as a flashbot tx
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata:
    - from - the address that initiated the tx
    - to - the address that was interacted with
    - hash - the transaction hash
    - blockNumber - the block number of the tx
  - Addresses contain the list of contracts that were impacted

## Test Data

In order to test the bot's behavior, replace `flashbotsUrl` variable in `agent.js` at L4, with one of the following urls and run `npm start`.

- `https://blocks.flashbots.net/v1/blocks?block_number=15725067` (Temple DAO Exploit)
- `https://blocks.flashbots.net/v1/blocks?block_number=15794364` (Olympus DAO Exploit)
