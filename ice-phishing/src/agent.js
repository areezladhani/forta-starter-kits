const { ethers, getEthersProvider } = require("forta-agent");
const LRU = require("lru-cache");
const { default: axios } = require("axios");
const {
  createHighNumApprovalsAlertERC20,
  createHighNumApprovalsInfoAlertERC20,
  createHighNumApprovalsAlertERC721,
  createHighNumApprovalsInfoAlertERC721,
  createHighNumTransfersAlert,
  createHighNumTransfersLowSeverityAlert,
  createPermitTransferAlert,
  createPermitTransferMediumSeverityAlert,
  createApprovalForAllAlertERC721,
  createApprovalForAllInfoAlertERC721,
  createApprovalForAllAlertERC1155,
  createApprovalForAllInfoAlertERC1155,
  createPermitAlert,
  createPermitInfoAlert,
  createPermitScamAlert,
  createPermitScamCreatorAlert,
  createPermitSuspiciousContractAlert,
  createApprovalScamAlert,
  createApprovalScamCreatorAlert,
  createApprovalSuspiciousContractAlert,
  createTransferScamAlert,
  createTransferScamCreatorAlert,
  createTransferSuspiciousContractAlert,
  getAddressType,
  getContractCreator,
  getBalance,
  getERC1155Balance,
  getSuspiciousContracts,
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
const approvalsInfoSeverity = {};
const approvalsERC20InfoSeverity = {};
const approvalsERC721InfoSeverity = {};
const approvalsForAll721InfoSeverity = {};
const approvalsForAll1155InfoSeverity = {};
const permissions = {};
const permissionsInfoSeverity = {};
const transfers = {};
const transfersLowSeverity = {};

let scamAddresses = [];

// Every address is ~100B
// 100_000 addresses are 10MB
const cachedAddresses = new LRU({ max: 100_000 });

let chainId;

const provideInitialize = (provider) => {
  return async () => {
    ({ chainId } = await provider.getNetwork());
  };
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
      const { owner, spender, deadline, expiry, value } = func.args;

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

      if (txFrom !== owner) {
        if (
          (spenderType === AddressType.LowNumTxsUnverifiedContract ||
            spenderType === AddressType.EoaWithLowNonce ||
            spenderType === AddressType.ScamAddress) &&
          (msgSenderType === AddressType.LowNumTxsUnverifiedContract ||
            msgSenderType === AddressType.EoaWithLowNonce ||
            msgSenderType === AddressType.ScamAddress)
        ) {
          if (!permissions[spender]) permissions[spender] = [];
          permissions[spender].push({
            asset,
            owner,
            hash,
            deadline: deadline ? deadline : expiry,
            value: value ? value : 0,
          });
          if (spenderType !== AddressType.ScamAddress && msgSenderType !== AddressType.ScamAddress) {
            findings.push(createPermitAlert(txFrom, spender, owner, asset));
          } else {
            const scamSnifferDB = await axios.get(
              "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
            );
            const scamDomains = Object.keys(scamSnifferDB.data).filter(
              (key) =>
                scamSnifferDB.data[key].includes(txFrom.toLowerCase()) ||
                scamSnifferDB.data[key].includes(spender.toLowerCase())
            );
            let _scamAddresses = [];
            if (spenderType === AddressType.ScamAddress) {
              _scamAddresses.push(spender);
            }
            if (msgSenderType === AddressType.ScamAddress) {
              _scamAddresses.push(txFrom);
            }
            findings.push(createPermitScamAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains));
          }
        } else if (
          (spenderType === AddressType.LowNumTxsVerifiedContract || spenderType === AddressType.EoaWithHighNonce) &&
          (msgSenderType === AddressType.LowNumTxsVerifiedContract || msgSenderType === AddressType.EoaWithHighNonce)
        ) {
          let spenderContractCreator,
            spenderContractCreatorType,
            msgSenderContractCreator,
            msgSenderContractCreatorType;
          if (spenderType === AddressType.LowNumTxsVerifiedContract) {
            suspiciousContracts.forEach((contract) => {
              if (contract.address === spender) {
                findings.push(createPermitSuspiciousContractAlert(txFrom, spender, owner, asset, contract));
              }
            });
            spenderContractCreator = await getContractCreator(spender, chainId);
            if (spenderContractCreator) {
              spenderContractCreatorType = await getAddressType(
                spenderContractCreator,
                scamAddresses,
                cachedAddresses,
                provider,
                blockNumber,
                chainId,
                false
              );
            }
          }
          if (msgSenderType === AddressType.LowNumTxsVerifiedContract) {
            suspiciousContracts.forEach((contract) => {
              if (contract.address === txFrom) {
                findings.push(createPermitSuspiciousContractAlert(txFrom, spender, owner, asset, contract));
              }
            });
            msgSenderContractCreator = await getContractCreator(txFrom, chainId);
            if (msgSenderContractCreator) {
              msgSenderContractCreatorType = await getAddressType(
                msgSenderContractCreator,
                scamAddresses,
                cachedAddresses,
                provider,
                blockNumber,
                chainId,
                false
              );
            }
          }

          if (
            (spenderContractCreator && spenderContractCreatorType === AddressType.ScamAddress) ||
            (msgSenderContractCreator && msgSenderContractCreatorType === AddressType.ScamAddress)
          ) {
            const scamSnifferDB = await axios.get(
              "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
            );
            const scamDomains = Object.keys(scamSnifferDB.data).filter(
              (key) =>
                scamSnifferDB.data[key].includes(msgSenderContractCreator.toLowerCase()) ||
                scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
            );
            let _scamAddresses = [];
            if (spenderContractCreatorType === AddressType.ScamAddress) {
              _scamAddresses.push(spenderContractCreator);
            }
            if (msgSenderContractCreator === AddressType.ScamAddress) {
              _scamAddresses.push(msgSenderContractCreator);
            }
            if (_scamAddresses.length > 0) {
              findings.push(createPermitScamCreatorAlert(txFrom, spender, owner, asset, _scamAddresses, scamDomains));
            }
          }

          if (!permissionsInfoSeverity[spender]) permissionsInfoSeverity[spender] = [];
          permissionsInfoSeverity[spender].push({
            asset,
            owner,
            hash,
            deadline: deadline ? deadline : expiry,
            value: value ? value : 0,
          });
          findings.push(createPermitInfoAlert(txFrom, spender, owner, asset));
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
      if (
        ownerType === AddressType.LowNumTxsUnverifiedContract ||
        ownerType === AddressType.HighNumTxsUnverifiedContract ||
        ownerType === AddressType.LowNumTxsVerifiedContract ||
        ownerType === AddressType.HighNumTxsVerifiedContract
      )
        return;

      // Skip if the spender
      // is verified contract with high number of txs
      // is unverified contract with high number of txs
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
        spenderType === AddressType.HighNumTxsVerifiedContract ||
        spenderType === AddressType.HighNumTxsUnverifiedContract ||
        spenderType.startsWith("Ignored")
      ) {
        return;
      } else if (
        spenderType === AddressType.EoaWithHighNonce ||
        spenderType === AddressType.LowNumTxsVerifiedContract
      ) {
        // Initialize the approvals array for the spender if it doesn't exist
        if (!approvalsInfoSeverity[spender]) approvalsInfoSeverity[spender] = [];
      } else {
        if (!approvals[spender]) approvals[spender] = [];
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (isApprovalForAll) {
          const assetCode = await provider.getCode(asset);
          if (assetCode.includes(safeBatchTransferFrom1155Sig)) {
            if (!approvalsForAll1155InfoSeverity[spender]) approvalsForAll1155InfoSeverity[spender] = [];
            approvalsForAll1155InfoSeverity[spender].push({
              asset,
              owner,
              hash,
              timestamp,
            });
          } else {
            if (!approvalsForAll721InfoSeverity[spender]) approvalsForAll721InfoSeverity[spender] = [];
            approvalsForAll721InfoSeverity[spender].push({
              asset,
              owner,
              hash,
              timestamp,
            });
          }
        } else if (tokenId) {
          if (!approvalsERC721InfoSeverity[spender]) approvalsERC721InfoSeverity[spender] = [];
          approvalsERC721InfoSeverity[spender].push({
            asset,
            owner,
            hash,
            timestamp,
          });
        } else {
          if (!approvalsERC20InfoSeverity[spender]) approvalsERC20InfoSeverity[spender] = [];
          approvalsERC20InfoSeverity[spender].push({
            asset,
            owner,
            hash,
            timestamp,
          });
        }

        // Update the approvals for the spender
        approvalsInfoSeverity[spender].push({
          asset,
          owner,
          hash,
          timestamp,
          tokenId,
          isApprovalForAll,
        });
      } else {
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

        // Update the approvals for the spender
        approvals[spender].push({
          asset,
          owner,
          hash,
          timestamp,
          tokenId,
          isApprovalForAll,
        });
      }

      console.log("Detected possible malicious approval");
      console.log(`owner: ${owner}`);
      console.log(`spender: ${spender}`);
      console.log(`asset: ${asset}`);

      for (const _approvals of [
        approvalsERC20,
        approvalsERC721,
        approvalsForAll721,
        approvalsForAll1155,
        approvals,
        approvalsERC20InfoSeverity,
        approvalsERC721InfoSeverity,
        approvalsForAll721InfoSeverity,
        approvalsForAll1155InfoSeverity,
        approvalsInfoSeverity,
      ]) {
        if (!_approvals[spender]) continue;
        _approvals[spender].filter((a) => timestamp - a.timestamp < TIME_PERIOD);
      }
      if (spenderType === AddressType.ScamAddress || spenderType === AddressType.LowNumTxsVerifiedContract) {
        const scamSnifferDB = await axios.get(
          "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
        );
        if (spenderType === AddressType.ScamAddress) {
          const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
            scamSnifferDB.data[key].includes(spender.toLowerCase())
          );
          findings.push(createApprovalScamAlert(spender, owner, asset, scamDomains));
        } else {
          suspiciousContracts.forEach((contract) => {
            if (contract.address === spender) {
              findings.push(createApprovalSuspiciousContractAlert(spender, owner, asset, contract.creator));
            }
          });

          const spenderContractCreator = await getContractCreator(spender, chainId);
          if (spenderContractCreator) {
            const scamDomains = Object.keys(scamSnifferDB.data).filter((key) =>
              scamSnifferDB.data[key].includes(spenderContractCreator.toLowerCase())
            );
            if (scamDomains.length > 0) {
              findings.push(createApprovalScamCreatorAlert(spender, spenderContractCreator, owner, asset, scamDomains));
            }
          }
        }
      }

      // Ignore the address until the end of the period if there are a lot of approvals
      if (approvals[spender] && approvals[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithLowNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      } else if (approvalsInfoSeverity[spender] && approvalsInfoSeverity[spender].length > maxAddressAlertsPerPeriod) {
        const newType =
          spenderType === AddressType.EoaWithHighNonce ? AddressType.IgnoredEoa : AddressType.IgnoredContract;
        cachedAddresses.set(spender, newType);
      }

      if (spenderType === AddressType.EoaWithHighNonce || spenderType === AddressType.LowNumTxsVerifiedContract) {
        if (approvalsERC20InfoSeverity[spender] && approvalsERC20InfoSeverity[spender].length > approveCountThreshold) {
          findings.push(createHighNumApprovalsInfoAlertERC20(spender, approvalsInfoSeverity[spender]));
        }

        if (
          approvalsERC721InfoSeverity[spender] &&
          approvalsERC721InfoSeverity[spender].length > approveCountThreshold
        ) {
          findings.push(createHighNumApprovalsInfoAlertERC721(spender, approvalsInfoSeverity[spender]));
        }

        if (isApprovalForAll) {
          if (
            approvalsForAll721InfoSeverity[spender] &&
            approvalsForAll721InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            findings.push(createApprovalForAllInfoAlertERC721(spender, owner, asset));
          } else if (
            approvalsForAll1155InfoSeverity[spender] &&
            approvalsForAll1155InfoSeverity[spender].length > approveForAllCountThreshold
          ) {
            findings.push(createApprovalForAllInfoAlertERC1155(spender, owner, asset));
          }
        }
      } else {
        if (approvalsERC20[spender] && approvalsERC20[spender].length > approveCountThreshold) {
          findings.push(createHighNumApprovalsAlertERC20(spender, approvals[spender]));
        }

        if (approvalsERC721[spender] && approvalsERC721[spender].length > approveCountThreshold) {
          findings.push(createHighNumApprovalsAlertERC721(spender, approvals[spender]));
        }

        if (isApprovalForAll) {
          if (approvalsForAll721[spender] && approvalsForAll721[spender].length > approveForAllCountThreshold) {
            findings.push(createApprovalForAllAlertERC721(spender, owner, asset));
          } else if (
            approvalsForAll1155[spender] &&
            approvalsForAll1155[spender].length > approveForAllCountThreshold
          ) {
            findings.push(createApprovalForAllAlertERC1155(spender, owner, asset));
          }
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

      const txFromType = await getAddressType(
        txFrom,
        scamAddresses,
        cachedAddresses,
        provider,
        blockNumber,
        chainId,
        false
      );
      const toType = await getAddressType(to, scamAddresses, cachedAddresses, provider, blockNumber, chainId, false);
      if (txFromType === AddressType.ScamAddress || toType === AddressType.ScamAddress) {
        const scamSnifferDB = await axios.get(
          "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
        );
        const scamDomains = Object.keys(scamSnifferDB.data).filter(
          (key) =>
            scamSnifferDB.data[key].includes(txFrom.toLowerCase()) || scamSnifferDB.data[key].includes(to.toLowerCase())
        );
        let _scamAddresses = [];
        if (toType === AddressType.ScamAddress) {
          _scamAddresses.push(to);
        }
        if (txFromType === AddressType.ScamAddress) {
          _scamAddresses.push(txFrom);
        }
        findings.push(createTransferScamAlert(txFrom, from, to, asset, _scamAddresses, scamDomains));
      }

      if (txFromType === AddressType.LowNumTxsVerifiedContract || toType === AddressType.LowNumTxsVerifiedContract) {
        let txFromContractCreator, txFromContractCreatorType, toContractCreator, toContractCreatorType;
        if (txFromType === AddressType.LowNumTxsVerifiedContract) {
          suspiciousContracts.forEach((contract) => {
            if (contract.address === txFrom) {
              findings.push(createTransferSuspiciousContractAlert(txFrom, from, to, asset, contract));
            }
          });
          txFromContractCreator = await getContractCreator(txFrom, chainId);
          if (txFromContractCreator) {
            txFromContractCreatorType = await getAddressType(
              txFromContractCreator,
              scamAddresses,
              cachedAddresses,
              provider,
              blockNumber,
              chainId,
              false
            );
          }
        }
        if (toType === AddressType.LowNumTxsVerifiedContract) {
          suspiciousContracts.forEach((contract) => {
            if (contract.address === to) {
              findings.push(createTransferSuspiciousContractAlert(txFrom, from, to, asset, contract));
            }
          });
          toContractCreator = await getContractCreator(to, chainId);
          if (toContractCreator) {
            toContractCreatorType = await getAddressType(
              toContractCreator,
              scamAddresses,
              cachedAddresses,
              provider,
              blockNumber,
              chainId,
              false
            );
          }
        }
        if (
          txFromContractCreatorType === AddressType.ScamAddress ||
          toContractCreatorType === AddressType.ScamAddress
        ) {
          const scamSnifferDB = await axios.get(
            "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/combined.json"
          );
          const scamDomains = Object.keys(scamSnifferDB.data).filter(
            (key) =>
              scamSnifferDB.data[key].includes(txFromContractCreator.toLowerCase()) ||
              scamSnifferDB.data[key].includes(toContractCreator.toLowerCase())
          );
          let _scamAddresses = [];
          if (toContractCreatorType === AddressType.ScamAddress) {
            _scamAddresses.push(toContractCreator);
          }
          if (txFromContractCreatorType === AddressType.ScamAddress) {
            _scamAddresses.push(txFromContractCreator);
          }
          findings.push(createTransferScamCreatorAlert(txFrom, from, to, asset, _scamAddresses, scamDomains));
        }
      }

      // Check if we monitor the spender
      const spenderApprovals = approvals[txFrom];
      const spenderApprovalsInfoSeverity = approvalsInfoSeverity[txFrom];
      const spenderPermissions = permissions[txFrom];
      const spenderPermissionsInfoSeverity = permissionsInfoSeverity[txFrom];
      if (!spenderApprovals && !spenderApprovalsInfoSeverity && !spenderPermissions && !spenderPermissionsInfoSeverity)
        return;

      spenderPermissions?.forEach((permission) => {
        if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
          if (!permission.value || permission.value.toString() === value.toString()) {
            findings.push(createPermitTransferAlert(txFrom, from, to, asset, value));
          }
        }
      });

      spenderPermissionsInfoSeverity?.forEach((permission) => {
        if (permission.asset === asset && permission.owner === from && permission.deadline > timestamp) {
          if (!permission.value || permission.value.toString() === value.toString()) {
            findings.push(createPermitTransferMediumSeverityAlert(txFrom, from, to, asset, value));
          }
        }
      });

      if (spenderApprovals) {
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
          if (value || (values && values.length > 0)) {
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
      }

      if (spenderApprovalsInfoSeverity) {
        // Check if we have caught the approval
        // For ERC20: Check if there is an approval from the owner that isn't from the current tx
        // For ERC721: Check if the tokenId is approved or if there is an ApprovalForAll
        const hasMonitoredApproval = tokenId
          ? spenderApprovalsInfoSeverity
              .filter((a) => a.owner === from)
              .some((a) => a.isApprovalForAll || a.tokenId.eq(tokenId) || tokenIds?.includes(a.tokenId))
          : spenderApprovalsInfoSeverity.find((a) => a.owner === from && a.asset === asset)?.timestamp < timestamp;

        if (!hasMonitoredApproval) return;

        // Initialize the transfers array for the spender if it doesn't exist
        if (!transfersLowSeverity[txFrom]) transfersLowSeverity[txFrom] = [];

        console.log("Detected possible malicious transfer of approved assets");
        console.log(`owner: ${from}`);
        console.log(`spender: ${txFrom}`);
        console.log(`asset: ${asset}`);

        // Update the transfers for the spender
        transfersLowSeverity[txFrom].push({
          asset,
          owner: from,
          hash,
          timestamp,
        });

        // Filter out old transfers
        transfersLowSeverity[txFrom] = transfersLowSeverity[txFrom].filter(
          (a) => timestamp - a.timestamp < TIME_PERIOD
        );

        if (transfersLowSeverity[txFrom].length > transferCountThreshold) {
          if (value || (values && values.length > 0)) {
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
          findings.push(createHighNumTransfersLowSeverityAlert(txFrom, transfersLowSeverity[txFrom]));
        }
      }
    })
  );

  return findings;
};

let lastTimestamp = 0;
let init = false;
let suspiciousContracts = new Set();

const provideHandleBlock = (getSuspiciousContracts) => async (blockEvent) => {
  const { timestamp, number } = blockEvent.block;
  if (!init) {
    suspiciousContracts = await getSuspiciousContracts(chainId, number, init);
  } else {
    const newSuspiciousContracts = await getSuspiciousContracts(chainId, number, init);
    newSuspiciousContracts.forEach((contract) => suspiciousContracts.add(contract));
  }
  init = true;

  const scamSnifferResponse = await axios.get(
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
  );
  scamAddresses = scamSnifferResponse.data;
  // Convert to checksum addresses
  scamAddresses = scamAddresses.map((address) => ethers.utils.getAddress(address));

  // Clean the data every timePeriodDays
  if (timestamp - lastTimestamp > TIME_PERIOD) {
    console.log("Cleaning");
    console.log(`Approvals before: ${Object.keys(approvals).length}`);
    console.log(`Approvals ERC20 before: ${Object.keys(approvalsERC20).length}`);
    console.log(`Approvals ERC721 before: ${Object.keys(approvalsERC721).length}`);
    console.log(`ApprovalsForAll ERC721 before: ${Object.keys(approvalsForAll721).length}`);
    console.log(`ApprovalsForAll ERC1155 before: ${Object.keys(approvalsForAll1155).length}`);
    console.log(`Permissions before: ${Object.keys(permissions).length}`);
    console.log(`Transfers before: ${Object.keys(transfers).length}`);
    console.log(`Approvals Info Severity before: ${Object.keys(approvalsInfoSeverity).length}`);
    console.log(`Approvals ERC20 Info Severity before: ${Object.keys(approvalsERC20InfoSeverity).length}`);
    console.log(`Approvals ERC721 Info Severity before: ${Object.keys(approvalsERC721InfoSeverity).length}`);
    console.log(`ApprovalsForAll ERC721 Info Severity before: ${Object.keys(approvalsForAll721InfoSeverity).length}`);
    console.log(`ApprovalsForAll ERC1155 Info Severity before: ${Object.keys(approvalsForAll1155InfoSeverity).length}`);
    console.log(`Permissions Info Severity before: ${Object.keys(permissionsInfoSeverity).length}`);
    console.log(`Transfers Low Severity before: ${Object.keys(transfersLowSeverity).length}`);

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

    Object.keys(permissions).forEach((spender) => {
      permissions[spender] = permissions[spender].filter((entry) => entry.deadline > timestamp);
      if (!(permissions[spender].length > 0)) {
        delete permissions[spender];
      }
    });

    Object.entries(transfers).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete transfers[spender];
      }
    });

    Object.entries(approvalsInfoSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsInfoSeverity[spender];
      }
    });

    Object.entries(approvalsERC20InfoSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsERC20InfoSeverity[spender];
      }
    });

    Object.entries(approvalsERC721InfoSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsERC721InfoSeverity[spender];
      }
    });

    Object.entries(approvalsForAll721InfoSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsForAll721InfoSeverity[spender];
      }
    });

    Object.entries(approvalsForAll1155InfoSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the approvals if the last approval for a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete approvalsForAll1155InfoSeverity[spender];
      }
    });

    Object.keys(permissionsInfoSeverity).forEach((spender) => {
      permissionsInfoSeverity[spender] = permissionsInfoSeverity[spender].filter((entry) => entry.deadline > timestamp);
      if (!(permissionsInfoSeverity[spender].length > 0)) {
        delete permissionsInfoSeverity[spender];
      }
    });

    Object.entries(transfersLowSeverity).forEach(([spender, data]) => {
      const { length } = data;
      // Clear the transfers if the last transfer from a spender is more than timePeriodDays ago
      if (timestamp - data[length - 1].timestamp > TIME_PERIOD) {
        delete transfersLowSeverity[spender];
      }
    });

    console.log(`Approvals after: ${Object.keys(approvals).length}`);
    console.log(`Approvals ERC20 after: ${Object.keys(approvalsERC20).length}`);
    console.log(`Approvals ERC721 after: ${Object.keys(approvalsERC721).length}`);
    console.log(`ApprovalsForAll ERC721 after: ${Object.keys(approvalsForAll721).length}`);
    console.log(`ApprovalsForAll ERC1155 after: ${Object.keys(approvalsForAll1155).length}`);
    console.log(`Permissions after: ${Object.keys(permissions).length}`);
    console.log(`Transfers after: ${Object.keys(transfers).length}`);
    console.log(`Approvals Info Severity after: ${Object.keys(approvalsInfoSeverity).length}`);
    console.log(`Approvals ERC20 Info Severity after: ${Object.keys(approvalsERC20InfoSeverity).length}`);
    console.log(`Approvals ERC721 Info Severity after: ${Object.keys(approvalsERC721InfoSeverity).length}`);
    console.log(`ApprovalsForAll ERC721 Info Severity after: ${Object.keys(approvalsForAll721InfoSeverity).length}`);
    console.log(`ApprovalsForAll ERC1155 Info Severity after: ${Object.keys(approvalsForAll1155InfoSeverity).length}`);
    console.log(`Permissions Info Severity after: ${Object.keys(permissionsInfoSeverity).length}`);
    console.log(`Transfers Low Severity after: ${Object.keys(transfersLowSeverity).length}`);

    // Reset ignored addresses
    cachedAddresses.entries(([address, type]) => {
      if (type === AddressType.IgnoredEoa) {
        cachedAddresses.set(address, AddressType.EoaWithLowNonce);
      }

      if (type === AddressType.IgnoredContract) {
        cachedAddresses.set(address, AddressType.LowNumTxsUnverifiedContract);
      }
    });

    lastTimestamp = timestamp;
  }
  return [];
};

module.exports = {
  initialize: provideInitialize(getEthersProvider()),
  provideInitialize,
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(getEthersProvider()),
  provideHandleBlock,
  handleBlock: provideHandleBlock(getSuspiciousContracts),
  getApprovals: () => approvals, // Exported for unit tests
  getERC20Approvals: () => approvalsERC20, // Exported for unit tests
  getERC721Approvals: () => approvalsERC721, // Exported for unit tests
  getERC721ApprovalsForAll: () => approvalsForAll721, // Exported for unit tests
  getERC1155ApprovalsForAll: () => approvalsForAll1155, // Exported for unit tests
  getPermissions: () => permissions, // Exported for unit tests
  getTransfers: () => transfers, // Exported for unit tests
  getApprovalsInfoSeverity: () => approvalsInfoSeverity, // Exported for unit tests
  getERC20ApprovalsInfoSeverity: () => approvalsERC20InfoSeverity, // Exported for unit tests
  getERC721ApprovalsInfoSeverity: () => approvalsERC721InfoSeverity, // Exported for unit tests
  getERC721ApprovalsForAllInfoSeverity: () => approvalsForAll721InfoSeverity, // Exported for unit tests
  getERC1155ApprovalsForAllInfoSeverity: () => approvalsForAll1155InfoSeverity, // Exported for unit tests
  getPermissionsInfoSeverity: () => permissionsInfoSeverity, // Exported for unit tests
  getTransfersLowSeverity: () => transfersLowSeverity, // Exported for unit tests
  getCachedAddresses: () => cachedAddresses, // Exported for unit tests,
  getSuspiciousContracts: () => suspiciousContracts, // Exported for unit tests
  resetLastTimestamp: () => {
    lastTimestamp = 0;
  },
  resetInit: () => {
    init = false;
  },
};
