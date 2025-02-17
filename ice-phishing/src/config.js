const etherscanApis = {
  1: {
    key: "YourApiKeyToken",
    urlContract: "https://api.etherscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api.etherscan.io/api?module=account&action=txlist",
    urlContractCreation: "https://api.etherscan.io/api?module=contract&action=getcontractcreation",
  },
  10: {
    key: "YourApiKeyToken",
    urlContract: "https://api-optimistic.etherscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api-optimistic.etherscan.io/api?module=account&action=txlist",
    urlContractCreation: "https://api-optimistic.etherscan.io/api?module=contract&action=getcontractcreation",
  },
  56: {
    key: "YourApiKeyToken",
    urlContract: "https://api.bscscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.bscscan.com/api?module=account&action=txlist",
    urlContractCreation: "https://api.bscscan.com/api?module=contract&action=getcontractcreation",
  },
  137: {
    key: "YourApiKeyToken",
    urlContract: "https://api.polygonscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.polygonscan.com/api?module=account&action=txlist",
    urlContractCreation: "https://api.polygonscan.com/api?module=contract&action=getcontractcreation",
  },
  250: {
    key: "YourApiKeyToken",
    urlContract: "https://api.ftmscan.com/api?module=contract&action=getabi",
    urlAccount: "https://api.ftmscan.com/api?module=account&action=txlist",
    urlContractCreation: "https://api.ftmscan.com/api?module=contract&action=getcontractcreation",
  },
  42161: {
    key: "YourApiKeyToken",
    urlContract: "https://api.arbiscan.io/api?module=contract&action=getabi",
    urlAccount: "https://api.arbiscan.io/api?module=account&action=txlist",
    urlContractCreation: "https://api.arbiscan.io/api?module=contract&action=getcontractcreation",
  },
  43114: {
    key: "YourApiKeyToken",
    urlContract: "https://api.snowtrace.io/api?module=contract&action=getabi",
    urlAccount: "https://api.snowtrace.io/api?module=account&action=txlist",
    urlContractCreation: "https://api.snowtrace.io/api?module=contract&action=getcontractcreation",
  },
};

module.exports = {
  etherscanApis,
};
