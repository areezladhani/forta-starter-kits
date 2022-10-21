const { Finding, FindingSeverity, FindingType, getEthersProvider, ethers } = require("forta-agent");
const { default: axios } = require("axios");
const LRU = require("lru-cache");
const { nonceThreshold, contractTxsThreshold, etherscanApis } = require("../bot-config.json");
const { ERC_20_721_INTERFACE, ERC_1155_INTERFACE } = require("./utils");
const AddressType = require("./address-type");

// Computes the data needed for an alert
function getEventInformation(eventsArray) {
  const { length } = eventsArray;
  const firstTxHash = eventsArray[0].hash;
  const lastTxHash = eventsArray[length - 1].hash;

  // Remove duplicates
  const assets = [...new Set(eventsArray.map((e) => e.asset))];
  const accounts = [...new Set(eventsArray.map((e) => e.owner))];

  const days = Math.ceil((eventsArray[length - 1].timestamp - eventsArray[0].timestamp) / 86400);

  return {
    firstTxHash,
    lastTxHash,
    assets,
    accounts,
    days,
  };
}

function createHighNumApprovalsAlertERC20(spender, approvalsArray) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-20 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-20 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
    },
    addresses: assets,
  });
}

function createHighNumApprovalsAlertERC721(spender, approvalsArray) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(approvalsArray);
  return Finding.fromObject({
    name: "High number of accounts granted approvals for ERC-721 tokens",
    description: `${spender} obtained transfer approval for ${assets.length} ERC-721 tokens by ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      firstTxHash,
      lastTxHash,
    },
    addresses: assets,
  });
}

function createApprovalForAllAlertERC721(spender, owner, asset) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-721 tokens",
    description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      spender,
      owner,
    },
    addresses: [asset],
  });
}

function createApprovalForAllAlertERC1155(spender, owner, asset) {
  return Finding.fromObject({
    name: "Account got approval for all ERC-1155 tokens",
    description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner}`,
    alertId: "ICE-PHISHING-ERC-1155-APPROVAL-FOR-ALL",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      spender,
      owner,
    },
    addresses: [asset],
  });
}

function createPermitAlert(msgSender, spender, owner, asset) {
  return Finding.fromObject({
    name: "Account got permission for ERC-20 tokens",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-PERMIT",
    severity: FindingSeverity.Low,
    type: FindingType.Suspicious,
    metadata: {
      msgSender,
      spender,
      owner,
    },
    addresses: [asset],
  });
}

function createPermitScamAlert(msgSender, spender, owner, asset, scamAddresses, scamDomains) {
  return Finding.fromObject({
    name: "Known scam address was involved in an ERC-20 permission",
    description: `${msgSender} gave permission to ${spender} for ${owner}'s ERC-20 tokens`,
    alertId: "ICE-PHISHING-ERC20-SCAM-PERMIT",
    severity: FindingSeverity.High,
    type: FindingType.Suspicious,
    metadata: {
      scamAddresses,
      scamDomains,
      msgSender,
      spender,
      owner,
    },
    addresses: [asset],
  });
}

function createHighNumTransfersAlert(spender, transfersArray) {
  const { firstTxHash, lastTxHash, assets, accounts, days } = getEventInformation(transfersArray);
  return Finding.fromObject({
    name: "Previously approved assets transferred",
    description: `${spender} transferred ${assets.length} assets from ${accounts.length} accounts over period of ${days} days.`,
    alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
    severity: FindingSeverity.High,
    type: FindingType.Exploit,
    metadata: {
      firstTxHash,
      lastTxHash,
    },
    addresses: assets,
  });
}

function createPermitTransferAlert(spender, owner, receiver, asset, value) {
  return Finding.fromObject({
    name: "Previously permitted assets transferred",
    description: `${spender} transferred ${value} tokens from ${from} to ${to}`,
    alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
    severity: FindingSeverity.Critical,
    type: FindingType.Exploit,
    metadata: {
      spender,
      owner,
      receiver,
    },
    addresses: asset,
  });
}

function getEtherscanContractUrl(address, chainId) {
  const { urlContract, key } = etherscanApis[chainId];
  return `${urlContract}&address=${address}&apikey=${key}`;
}

function getEtherscanAddressUrl(address, chainId) {
  const { urlAccount, key } = etherscanApis[chainId];
  return `${urlAccount}&address=${address}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey=${key}`;
}

async function getEoaType(address, blockNumber) {
  const nonce = await getEthersProvider().getTransactionCount(address, blockNumber);
  return nonce > nonceThreshold ? AddressType.EoaWithHighNonce : AddressType.EoaWithLowNonce;
}

async function getContractType(address, chainId) {
  let result;
  result = await axios.get(getEtherscanContractUrl(address, chainId));
  if (result.data.message === "NOTOK") {
    console.log(`rate limit reached; skipping check for ${address}`);
    return null;
  }

  const isVerified = result.data.status === "1";

  if (isVerified) {
    return AddressType.VerifiedContract;
  }

  result = await axios.get(getEtherscanAddressUrl(address, chainId));
  if (result.data.message === "NOTOK") {
    console.log(`rate limit reached; skipping check for ${address}`);
    return null;
  }
  const hasHighNumberOfTotalTxs = result.data.result.length > contractTxsThreshold;
  return hasHighNumberOfTotalTxs ? AddressType.HighNumTxsUnverifiedContract : AddressType.UnverifiedContract;
}

async function getAddressType(address, cachedAddresses, blockNumber, chainId, isOwner) {
  if (cachedAddresses.has(address)) {
    const type = cachedAddresses.get(address);

    // Don't update the cached address if
    // the check is for the owner
    // the type cannot be changed back
    // the address is ignored
    if (
      isOwner ||
      type === AddressType.EoaWithHighNonce ||
      type === AddressType.VerifiedContract ||
      type.startsWith("Ignored")
    ) {
      return type;
    }

    const getTypeFn =
      type === AddressType.EoaWithLowNonce
        ? async () => getEoaType(address, blockNumber)
        : async () => getContractType(address, chainId);
    const newType = await getTypeFn(address, blockNumber);

    if (newType && newType !== type) cachedAddresses.set(address, newType);
    return newType;
  }

  // If the address is not in the cache check if it is a contract
  const code = await getEthersProvider().getCode(address);
  const isEoa = code === "0x";

  // Skip etherscan call and directly return unverified if checking for the owner
  if (isOwner && !isEoa) return AddressType.UnverifiedContract;

  const getTypeFn = isEoa
    ? async () => getEoaType(address, blockNumber)
    : async () => getContractType(address, chainId);
  const type = await getTypeFn(address, blockNumber);

  if (type) cachedAddresses.set(address, type);
  return type;
}

const cachedBalances = new LRU({ max: 100_000 });

async function getBalance(token, account, provider, blockNumber) {
  const key = `${account}-${token}-${blockNumber}`;
  if (cachedBalances.has(key)) return cachedBalances.get(key);
  const tokenContract = new ethers.Contract(token, ERC_20_721_INTERFACE, provider);
  const balance = await tokenContract.balanceOf(account, {
    blockTag: blockNumber,
  });
  cachedBalances.set(key, balance);
  return balance;
}

async function getERC1155Balance(token, id, account, provider, blockNumber) {
  const key = `${account}-${token} -${id}-${blockNumber}`;
  if (cachedBalances.has(key)) return cachedBalances.get(key);
  const tokenContract = new ethers.Contract(token, ERC_1155_INTERFACE, provider);
  const balance = await tokenContract.balanceOf(account, id, {
    blockTag: blockNumber,
  });
  cachedBalances.set(key, balance);
  return balance;
}

module.exports = {
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumTransfersAlert,
  createPermitTransferAlert,
  createApprovalForAllAlertERC721,
  createApprovalForAllAlertERC1155,
  createPermitAlert,
  createPermitScamAlert,
  getAddressType,
  getBalance,
  getERC1155Balance,
};
