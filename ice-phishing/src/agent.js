const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const { default: axios } = require("axios");
const {
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumTransfersAlert,
  createPermitTransferAlert,
  createApprovalForAllAlertERC721,
  createApprovalForAllAlertERC1155,
  createPermitAlert,
  createPermitScamAlert,
  createApprovalScamAlert,
  createTransferScamAlert,
  getAddressType,
  getBalance,
  getERC1155Balance,
} = require("./helper");
const {
  approveCountThreshold,
  approveForAllCountThreshold,
  transferCountThreshold,
  maxAddressAlertsPerPeriod,
} = require("../bot-config.json");
const {
  TIME_PERIOD,
  ADDRESS_ZERO,
  safeBatchTransferFrom1155Sig,
  permitFunctionABI,
  daiPermitFunctionABI,
  approvalEventErc20ABI,
  approvalEventErc721ABI,
  approvalForAllEventABI,
  transferEventErc20ABI,
  transferEventErc721ABI,
  erc1155transferEventABI,
} = require("./utils");
const AddressType = require("./address-type");

const approvals = {};
const approvalsERC20 = {};
const approvalsERC721 = {};
const approvalsForAll721 = {};
const approvalsForAll1155 = {};
const permissions = {};
const transfers = {};
let scamAddresses = [];

// Every address is ~100B
// 100_000 addresses are 10MB
const cachedAddresses = new LRU({ max: 100_000 });

let chainId;

const initialize = async () => {
  ({ chainId } = await getEthersProvider().getNetwork());
};

const provideHandleTransaction = (provider) => async (txEvent) => {
  const findings = [];

  const { hash, timestamp, blockNumber, from: f } = txEvent;
  const txFrom = ethers.utils.getAddress(f);

  const permitFunctions = [
    ...txEvent.filterFunction(permitFunctionABI),
    ...txEvent.filterFunction(daiPermitFunctionABI),
  ];

  // ERC20 and ERC721 approvals and transfers have the same signature
  // so we need to collect them seperately
  const approvalEvents = [
    ...txEvent.filterLog(approvalEventErc20ABI),
    ...txEvent.filterLog(approvalEventErc721ABI),
    ...txEvent.filterLog(approvalForAllEventABI),
  ];

  const transferEvents = [
    ...txEvent.filterLog(transferEventErc20ABI),
    ...txEvent.filterLog(transferEventErc721ABI),
    ...txEvent.filterLog(erc1155transferEventABI),
  ];

  await Promise.all(
    permitFunctions.map(async (func) => {
      const { address: asset } = func;
      const { owner, spender, deadline, value } = func.args;

      const msgSenderType = await getAddressType(
        txFrom,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );

      const spenderType = await getAddressType(
        spender,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );

      if (
        txFrom !== owner &&
        (spenderType === AddressType.HighNumTxsUnverifiedContract ||
          spenderType === AddressType.EoaWithLowNonce ||
          spenderType === AddressType.ScamAddress) &&
        (msgSenderType === AddressType.HighNumTxsUnverifiedContract ||
          msgSenderType === AddressType.EoaWithLowNonce ||
          msgSenderType === AddressType.ScamAddress)
      ) {
        if (!permissions[spender]) permissions[spender] = [];
        permissions[spender].push({
          asset,
          owner,
          hash,
          deadline,
          value: value ? value : 0,
        });
        if (spenderType !== AddressType.ScamAddress && msgSenderType !== AddressType.ScamAddress) {
          findings.push(createPermitAlert(txFrom, spender, owner, asset));
        } else {
          const scamSnifferDB = await axios.get(
            "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
          ).data;
          const scamDomains = scamSnifferDB.filter(
            (key) => scamSnifferDB[key].includes(txFrom) || scamSnifferDB[key].includes(spender)
          );
          let _scamAddresses;
          if (spenderType === AddressType.ScamAddress) {
            _scamAddresses.push(spender);
          }
          if (msgSenderType === AddressType.ScamAddress) {
            _scamAddresses.push(txFrom);
          }
          findings.push(createPermitScamAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains));
        }
      }
    })
  );

  await Promise.all(
    approvalEvents.map(async (event) => {
      const { address: asset, name } = event;
      const { owner, spender, value, tokenId, approved } = event.args;

      const isApprovalForAll = name === "ApprovalForAll";

      // Filter out approval revokes
      if (isApprovalForAll && !approved) return;
      if (value?.eq(0)) return;
      if (spender === ADDRESS_ZERO) return;

      // When transfering ERC20 tokens an Approval event is emitted with lower value
      // We should ignore these Approval events because they are duplicates
      const isAlreadyApproved = tokenId ? false : approvals[spender]?.some((a) => a.owner === owner);

      if (isAlreadyApproved) return;

      // Skip if the owner is not EOA
      const ownerType = await getAddressType(
        owner,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        true
      );
      if (ownerType === AddressType.UnverifiedContract || ownerType === AddressType.VerifiedContract) return;

      // Skip if the spender
      // has high nonce (probably CEX)
      // is verified contract
      // is unverified contracts with high number of txs
      // or is ignored address
      const spenderType = await getAddressType(
        spender,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );
      if (
        !spenderType ||
        spenderType === AddressType.EoaWithHighNonce ||
        spenderType === AddressType.VerifiedContract ||
        spenderType === AddressType.HighNumTxsUnverifiedContract ||
        spenderType.startsWith("Ignored")
      )
        return;

      // Initialize the approvals array for the spender if it doesn't exist
      if (!approvals[spender]) approvals[spender] = [];

      if (isApprovalForAll) {
        const assetCode = await provider.getCode(asset);
        if (assetCode.includes(safeBatchTransferFrom1155Sig)) {
          if (!approvalsForAll1155[spender]) approvalsForAll1155[spender] = [];
          approvalsForAll1155[spender].push({
            asset,
            owner,
            hash,
            timestamp,
          });
        } else {
          if (!approvalsForAll721[spender]) approvalsForAll721[spender] = [];
          approvalsForAll721[spender].push({
            asset,
            owner,
            hash,
            timestamp,
          });
        }
      } else if (tokenId) {
        if (!approvalsERC721[spender]) approvalsERC721[spender] = [];
        approvalsERC721[spender].push({
          asset,
          owner,
          hash,
          timestamp,
        });
      } else {
        if (!approvalsERC20[spender]) approvalsERC20[spender] = [];
        approvalsERC20[spender].push({
          asset,
          owner,
          hash,
          timestamp,
        });
      }

      // console.log("Detected possible malicious approval");
      // console.log(`owner: ${owner}`);
      // console.log(`spender: ${spender}`);
      // console.log(`asset: ${asset}`);

      // Update the approvals for the spender
      approvals[spender].push({
        asset,
        owner,
        hash,
        timestamp,
        tokenId,
        isApprovalForAll,
      });

      for (const _approvals of [approvalsERC20, approvalsERC721, approvalsForAll721, approvalsForAll1155, approvals]) {
        if (!_approvals[spender]) continue;
        _approvals[spender].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
      }

      if (spenderType === AddressType.ScamAddress) {
        const scamSnifferDB = await axios.get(
          "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
        ).data;
        const scamDomains = scamSnifferDB.filter((key) => scamSnifferDB[key].includes(spender));
        findings.push(createApprovalScamAlert(spender, owner, asset, scamDomains));
      }

      // Ignore the address until the end of the period if there are a lot of approvals
      if (approvals[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithLowNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      }

      if (approvalsERC20[spender] && approvalsERC20[spender].length > approveCountThreshold) {
        findings.push(createHighNumApprovalsAlertERC20(spender, approvals[spender]));
      }

      if (approvalsERC721[spender] && approvalsERC721[spender].length > approveCountThreshold) {
        findings.push(createHighNumApprovalsAlertERC721(spender, approvals[spender]));
      }

      if (isApprovalForAll) {
        if (approvalsForAll721[spender] && approvalsForAll721[spender].length > approveForAllCountThreshold) {
          findings.push(createApprovalForAllAlertERC721(spender, owner, asset));
        } else if (approvalsForAll1155[spender] && approvalsForAll1155[spender].length > approveForAllCountThreshold) {
          findings.push(createApprovalForAllAlertERC1155(spender, owner, asset));
        }
      }
    })
  );

  await Promise.all(
    transferEvents.map(async (event) => {
      const asset = event.address;
      const { from, to, value, values, tokenId, tokenIds } = event.args;

      // Filter out direct transfers and mints
      if (from === txFrom || from === ADDRESS_ZERO) return;

      // Check if we monitor the spender
      const spenderApprovals = approvals[txFrom];
      const spenderPermissions = permissions[txFrom];
      if (!spenderApprovals && !spenderPermissions) return;

      spenderPermissions?.forEach((permission) => {
        if (permission.asset === asset && permission.owner === from) {
          if (!permission.value || permission.value === value) {
            findings.push(createPermitTransferAlert(txFrom, from, to, asset, value));
          }
        }
      });

      const txFromType = getAddressType(txFrom, scamAddresses, cachedAddresses, provider, blockNumber, chainId, false);
      const toType = getAddressType(to, scamAddresses, cachedAddresses, provider, blockNumber, chainId, false);
      if (txFromType === AddressType.ScamAddress || toType === AddressType.ScamAddress) {
        const scamSnifferDB = await axios.get(
          "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
        ).data;
        const scamDomains = scamSnifferDB.filter(
          (key) => scamSnifferDB[key].includes(txFrom) || scamSnifferDB[key].includes(to)
        );
        let _scamAddresses;
        if (toType === AddressType.ScamAddress) {
          _scamAddresses.push(to);
        }
        if (txFromType === AddressType.ScamAddress) {
          _scamAddresses.push(txFrom);
        }
        findings.push(createTransferScamAlert(txFrom, from, to, asset, _scamAddresses, scamDomains));
      }

      // Check if we have caught the approval
      // For ERC20: Check if there is an approval from the owner that isn't from the current tx
      // For ERC721: Check if the tokenId is approved or if there is an ApprovalForAll
      const hasMonitoredApproval = tokenId
        ? spenderApprovals
            .filter((a) => a.owner === from)
            .some((a) => a.isApprovalForAll || a.tokenId.eq(tokenId) || tokenIds?.includes(a.tokenId))
        : spenderApprovals.find((a) => a.owner === from && a.asset === asset)?.timestamp < timestamp;

      if (!hasMonitoredApproval) return;

      // Initialize the transfers array for the spender if it doesn't exist
      if (!transfers[txFrom]) transfers[txFrom] = [];

      console.log("Detected possible malicious transfer of approved assets");
      console.log(`owner: ${from}`);
      console.log(`spender: ${txFrom}`);
      console.log(`asset: ${asset}`);

      // Update the transfers for the spender
      transfers[txFrom].push({
        asset,
        owner: from,
        hash,
        timestamp,
      });

      // Filter out old transfers
      transfers[txFrom] = transfers[txFrom].filter((a) => timestamp - a.timestamp < TIME_PERIOD);

      if (transfers[txFrom].length > transferCountThreshold) {
        if (value || values) {
          if (tokenIds) {
            tokenIds.forEach(async (tokenId) => {
              const balance = ethers.BigNumber.from(
                await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
              );
              if (!balance.eq(0)) return;
            });
          } else if (tokenId) {
            const balance = ethers.BigNumber.from(
              await getERC1155Balance(asset, tokenId, from, provider, txEvent.blockNumber)
            );
            if (!balance.eq(0)) return;
          } else {
            const balance = ethers.BigNumber.from(await getBalance(asset, from, provider, txEvent.blockNumber));
            if (!balance.eq(0)) return;
          }
        }
        findings.push(createHighNumTransfersAlert(txFrom, transfers[txFrom]));
      }
    })
  );

  return findings;
};

let lastTimestamp = 0;

const handleBlock = async (blockEvent) => {
  const scamSnifferResponse = await axios.get(
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
  );
  scamAddresses = scamSnifferResponse.data;

  const { timestamp } = blockEvent.block;

  // Clean the data every timePeriodDays
  if (timestamp - lastTimestamp > TIME_PERIOD) {
    console.log("Cleaning");
    console.log(`Approvals before: ${Object.keys(approvals).length}`);
    console.log(`Permissions before: ${Object.keys(permissions).length}`);
    console.log(`Transfers before: ${Object.keys(transfers).length}`);

    Object.entries(approvals).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvals[spender];
      }
    });

    Object.entries(approvalsERC20).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsERC20[spender];
      }
    });

    Object.entries(approvalsERC721).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsERC721[spender];
      }
    });

    Object.entries(approvalsForAll721).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsForAll721[spender];
      }
    });

    Object.entries(approvalsForAll1155).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsForAll1155[spender];
      }
    });

    Object.entries(permissions).forEach(([spender, data]) => {
      Object.entries(data).forEach((d) => {
        // Clear the permission if it has expired
        if (timestamp > d.deadline) {
          delete permissions[spender][d];
        }
      });
    });

    Object.entries(transfers).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete transfers[spender];
      }
    });

    console.log(`Approvals after: ${Object.keys(approvals).length}`);
    console.log(`Permissions after: ${Object.keys(permissions).length}`);
    console.log(`Transfers after: ${Object.keys(transfers).length}`);

    // Reset ignored addresses
    cachedAddresses.entries(([address, type]) => {
      if (type === AddressType.IgnoredEoa) {
        cachedAddresses.set(address, AddressType.EoaWithLowNonce);
      }

      if (type === AddressType.IgnoredContract) {
        cachedAddresses.set(address, AddressType.UnverifiedContract);
      }
    });

    lastTimestamp = timestamp;
  }
  return [];
};

module.exports = {
  initialize,
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(getEthersProvider()),
  handleBlock,
  getApprovals: () => approvals, // Exported for unit tests
  getERC20Approvals: () => approvalsERC20, // Exported for unit tests
  getERC721Approvals: () => approvalsERC721, // Exported for unit tests
  getTransfers: () => transfers, // Exported for unit tests
  getCachedAddresses: () => cachedAddresses, // Exported for unit tests
  getScamAddresses: () => scamAddresses, // Exported for unit tests
  resetLastTimestamp: () => {
    lastTimestamp = 0;
  },
};
