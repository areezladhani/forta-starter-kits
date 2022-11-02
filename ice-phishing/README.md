# Ice Phishing Bot

## Description

This bot detects if an account (EOA with low nonce or unverified contract with low number of transactions) gains a high number of approvals or an ERC20 permission and if it transfers the approved funds. It also does the same checks for EOAs with high nonce or verified contracts with low number of transactions and emits an alert of lower severity. Lastly, it checks if an account from the [ScamSniffer DB](https://github.com/scamsniffer/scam-database) is involved in an `Approval`/`Transfer`/`permit`.

> The `permit` function signatures detected by the bot are the EIP-2612's and MakerDAO DAI's.

## Supported Chains

- Ethereum
- Optimism
- Binance Smart Chain
- Polygon
- Fantom
- Arbitrum
- Avalanche

## Alerts

- ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS

  - Fired when an account gains high number of ERC-20 approvals
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS

  - Fired when an account gains high number of ERC-721 approvals
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-ERC721-APPROVAL-FOR-ALL

  - Fired when an account gains approval for all ERC-721s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the approved asset address

- ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL

  - Fired when an account gains approval for all ERC-1155s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the approved asset address

  - ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains high number of ERC-20 approvals
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains high number of ERC-721 approvals
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `firstTxHash` - hash of the first approval tx
    - `lastTxHash` - hash of the last approval tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains approval for all ERC-721s
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the approved asset address

- ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gains approval for all ERC-1155s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the approved asset address

- ICE-PHISHING-ERC20-PERMIT

  - Fired when an account (unverified contract with low number of transactions or EOA with low nonce) gives permission to another account for a victim's ERC-20s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `msgSender` - the account that called the asset's `permit` function
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the permitted asset address

  - ICE-PHISHING-ERC20-PERMIT-INFO

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) gives permission to another account for a victim's ERC-20s
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata:
    - `msgSender` - the account that called the asset's `permit` function
    - `spender` - the account that received the approval
    - `owner` - the owner of the assets
  - Addresses contain the permitted asset address

- ICE-PHISHING-ERC20-SCAM-PERMIT

  - Fired when a known scam address is involved in an ERC-20 permission.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the permission
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
    - Addresses contain the permitted asset address

- ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT

  - Fired when a verified contract, created by a scam account, is involved in an ERC-20 permission.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the permission
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
    - Addresses contain the permitted asset address

- ICE-PHISHING-ERC20-SUSPICIOUS-PERMIT

  - Fired when a known scam address is involved in an ERC-20 permission.
    - Severity is always set to "medium"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousContract` - The address of the suspicious contract
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the permission
      - `owner` - the owner of the assets
    - Addresses contain the permitted asset address

- ICE-PHISHING-SCAM-APPROVAL

  - Fired when a known scam address gets approval to spend assets.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamDomains` - The list of domains related to the scam addresses
      - `scamSpender` - the account that received the approval
      - `owner` - the owner of the assets
    - Addresses contain the approved asset address

- ICE-PHISHING-SCAM-CREATOR-APPROVAL

  - Fired when a verified contract, created by a known scam address, gets approval to spend assets.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `scamDomains` - The list of domains related to the scam addresses
      - `scamCreator` - The scam address that created the contract
      - `spender` - the contract that received the approval
      - `owner` - the owner of the assets
    - Addresses contain the approved asset address

- ICE-PHISHING-SUSPICIOUS-APPROVAL

  - Fired when a known scam address gets approval to spend assets.
    - Severity is always set to "medium"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousSpender` - the address of the suspicious spender
      - `owner` - the owner of the assets
    - Addresses contain the approved asset address

- ICE-PHISHING-SCAM-TRANSFER

  - Fired when a known scam address is involved in an asset transfer.
    - Severity is always set to "critical"
    - Type is always set to "exploit"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the transfer
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
    - Addresses contain the transferred asset address

- ICE-PHISHING-SCAM-CREATOR-TRANSFER

  - Fired when a verified contract, created by a known scam address, is involved in an asset transfer.
    - Severity is always set to "critical"
    - Type is always set to "exploit"
    - Metadata:
      - `scamAddresses` - The list of known scam addresses that were involved in the transfer
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
    - Addresses contain the transferred asset address

- ICE-PHISHING-SUSPICIOUS-TRANSFER

  - Fired when a suspicious contract is involved in an asset transfer.
    - Severity is always set to "high"
    - Type is always set to "suspicious"
    - Metadata:
      - `suspiciousContract` - The address of the suspicious contract
      - `msgSender` - The account that initiated the transfer
      - `owner` - The owner of the assets
      - `receiver` - The account that received the assets
    - Addresses contain the transferred asset address

- ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS

  - Fired when an account that gained high number of approvals starts transfering the approved assets
  - Severity is always set to "high"
  - Type is always set to "exploit"
  - Metadata:
    - `firstTxHash` - hash of the first transfer tx
    - `lastTxHash` - hash of the last transfer tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) that gained high number of approvals starts transfering the approved assets
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Metadata:
    - `firstTxHash` - hash of the first transfer tx
    - `lastTxHash` - hash of the last transfer tx
  - Addresses contain an array of the impacted assets

- ICE-PHISHING-PERMITTED-ERC20-TRANSFER

  - Fired when an account transfers tokens for which it was previously granted permission.
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Metadata:
    - `spender` - the account that transferred the tokens
    - `owner` - the owner of the assets
    - `receiver` - the account that received the tokens
  - Addresses contain the transferred asset address

- ICE-PHISHING-PERMITTED-ERC20-TRANSFER-MEDIUM

  - Fired when an account (verified contract with low number of transactions or EOA with high nonce) transfers tokens for which it was previously granted permission.
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata:
    - `spender` - the account that transferred the tokens
    - `owner` - the owner of the assets
    - `receiver` - the account that received the tokens
  - Addresses contain the transferred asset address

## Test Data

The bot behaviour can be verified with the following transactions on Ethereum:

- `npm run tx 0xc45f426dbae8cfa1f96722d5fccfe8036a356b6be2259ac9b1836a9c3286000f,0x70842e12f8698a3a12f8a015579c4152d6e65841d1c18a23e85b5127144a5490,0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34,0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869,0x36ee80b32a4248c4f1ca70fc78989b3ffe0def0a6824cb8591aff8110170769c,0xe01969b2c7dea539497d0413cf3b53f80a6f793f63637e6747991405e20dcaf4` - BadgerDAO attack (In order for more `Approval` alerts to be raised, set the `approveCountThreshold` in `bot-config.json` to `0` or `1`)
- `npm run tx 0x4ac7bb723c430d47b6871cc475da2661f9f2d848f6d9a220d125f33bc8850f7c,0x8f13bcbd56ef6c4ebdf1c18388ae4510be358b516aef4347b7d989b0340a1ae8,0x43337dadfd774ffdbb883f0935f1ba368d9fceb24a161e157cf4402e824dfbfd,0x519802e340fe178bb573b6ad840a2eb56ba2638cffc5791860aa4af2fa05b398` - Uniswap V3 attack (In order for an `ApprovalForAll` alert to be raised, set the `approveForAllCountThreshold` in `bot-config.json` to `0`)
