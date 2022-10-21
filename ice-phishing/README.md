# Ice Phishing Bot

## Description

This bot detects if an account (EOA with low nonce or unverified account with low number of transactions) gains a high number of approvals or an ERC20 permission and if it transfers the approved funds.

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

- ICE-PHISHING-ERC20-PERMIT

  - Fired when an account gives permission to another account for a victim's ERC-20s
  - Severity is always set to "low"
  - Type is always set to "suspicious"
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
      - `scamAddresses` - The list of known scam addresses that were involved in this permission
      - `scamDomains` - The list of domains related to the scam addresses
      - `msgSender` - the account that called the asset's `permit` function
      - `spender` - the account that received the approval
      - `owner` - the owner of the assets
    - Addresses contain the permitted asset address

- ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS

  - Fired when an account that gained high number of approvals starts transfering the approved assets
  - Severity is always set to "high"
  - Type is always set to "exploit"
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

## Test Data

The bot behaviour can be verified with the following transactions:

- `npm run tx 0xc45f426dbae8cfa1f96722d5fccfe8036a356b6be2259ac9b1836a9c3286000f,0x70842e12f8698a3a12f8a015579c4152d6e65841d1c18a23e85b5127144a5490,0x5e4c7966b0eaddaf63f1c89fc1c4c84812905ea79c6bee9d2ada2d2e5afe1f34,0x951babdddbfbbba81bbbb7991a959d9815e80cc5d9418d10e692f41541029869,0x36ee80b32a4248c4f1ca70fc78989b3ffe0def0a6824cb8591aff8110170769c,0xe01969b2c7dea539497d0413cf3b53f80a6f793f63637e6747991405e20dcaf4` - BadgerDAO attack
- `npm run tx 0x4ac7bb723c430d47b6871cc475da2661f9f2d848f6d9a220d125f33bc8850f7c,0x8f13bcbd56ef6c4ebdf1c18388ae4510be358b516aef4347b7d989b0340a1ae8,0x43337dadfd774ffdbb883f0935f1ba368d9fceb24a161e157cf4402e824dfbfd,0x519802e340fe178bb573b6ad840a2eb56ba2638cffc5791860aa4af2fa05b398` - Uniswap V3 attack
