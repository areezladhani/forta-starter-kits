const { FindingType, FindingSeverity, Finding, ethers, getEthersProvider } = require("forta-agent");
const axios = require("axios");
const { createAddress } = require("forta-agent-tools");
const {
  provideHandleTransaction,
  handleBlock,
  getApprovals,
  getERC20Approvals,
  getERC721Approvals,
  getERC721ApprovalsForAll,
  getERC1155ApprovalsForAll,
  getPermissions,
  getTransfers,
  getCachedAddresses,
  resetLastTimestamp,
} = require("./agent");

const approveCountThreshold = 2;
const approveForAllCountThreshold = 2;
const transferCountThreshold = 2;
const timePeriodDays = 30;
const nonceThreshold = 100;
const maxAddressAlertsPerPeriod = 3;

const spender = createAddress("0x01");
const owner1 = createAddress("0x02");
const owner2 = createAddress("0x03");
const owner3 = createAddress("0x04");
const asset = createAddress("0x05");
const asset2 = createAddress("0x06");

//const txFrom = createAddress("0x06");

// Mock the config file
jest.mock(
  "../bot-config.json",
  () => ({
    approveCountThreshold,
    approveForAllCountThreshold,
    transferCountThreshold,
    timePeriodDays,
    nonceThreshold,
    maxAddressAlertsPerPeriod,
  }),
  { virtual: true }
);

const mockBalanceOf = jest.fn();
// Mock axios and ethers provider
jest.mock("axios");
jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    getEthersProvider: jest.fn(),
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        balanceOf: mockBalanceOf,
      })),
    },
  };
});

const mockGetCode = jest.fn();
getEthersProvider.mockImplementation(() => ({
  getCode: () => "0x",
  getTransactionCount: () => 1,
}));

const mockApprovalForAllEvent = [
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner1,
      spender,
      approved: true,
    },
  },
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner2,
      spender,
      approved: true,
    },
  },
  {
    address: asset,
    name: "ApprovalForAll",
    args: {
      owner: owner3,
      spender,
      approved: true,
    },
  },
];

const mockPermitFunctionCall = {
  address: asset,
  args: {
    owner: owner1,
    spender,
    deadline: 9359543534435,
    value: ethers.BigNumber.from(210),
  },
};

const mockDAILikePermitFunctionCall = {
  address: asset,
  args: {
    owner: owner1,
    spender,
    expiry: 8359543534435,
  },
};

const mockApprovalERC20Events = [
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      value: ethers.BigNumber.from(5),
    },
  },
];

const mockApprovalERC721Events = [
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      tokenId: ethers.BigNumber.from(5),
    },
  },
];

const mockTransferEvents = [
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner1,
      to: createAddress("0x11"),
      value: ethers.BigNumber.from(210),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner2,
      value: ethers.BigNumber.from(1210),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner3,
      value: ethers.BigNumber.from(11210),
    },
  },
];

const mockApprovalERC20Events2 = [
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner1,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner2,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
  {
    address: asset2,
    name: "Approval",
    args: {
      owner: owner3,
      spender,
      value: ethers.BigNumber.from(10000005),
    },
  },
];

const mockTransferEvents2 = [
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner1,
      value: ethers.BigNumber.from(210),
    },
  },
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner2,
      value: ethers.BigNumber.from(1210),
    },
  },
  {
    address: asset2,
    name: "Transfer",
    args: {
      from: owner3,
      value: ethers.BigNumber.from(11210),
    },
  },
];

const mockTransferERC721Events = [
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner1,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner2,
      tokenId: ethers.BigNumber.from(5),
    },
  },
  {
    address: asset,
    name: "Transfer",
    args: {
      from: owner3,
      tokenId: ethers.BigNumber.from(5),
    },
  },
];

const mockTransferSingleEvents = [
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner1,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(1234),
    },
  },
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner2,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(122234),
    },
  },
  {
    address: asset,
    name: "TransferSingle",
    args: {
      from: owner3,
      tokenId: ethers.BigNumber.from(5),
      value: ethers.BigNumber.from(1122234),
    },
  },
];

const mockTransferBatchEvents = [
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner1,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(1234), ethers.BigNumber.from(1235)],
    },
  },
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner2,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(111234), ethers.BigNumber.from(111235)],
    },
  },
  {
    address: asset,
    name: "TransferBatch",
    args: {
      from: owner3,
      tokenIds: [ethers.BigNumber.from(4), ethers.BigNumber.from(5)],
      values: [ethers.BigNumber.from(189234), ethers.BigNumber.from(189235)],
    },
  },
];

const mockProviderGetCode = jest.fn();
const mockProviderGetTransactionCount = jest.fn();
describe("ice-phishing bot", () => {
  const mockProvider = {
    getCode: mockProviderGetCode,
    getTransactionCount: mockProviderGetTransactionCount,
  };

  describe("provideHandleTransaction", () => {
    let mockTxEvent = {};
    let handleTransaction;
    beforeAll(() => {
      const axiosResponse = { data: { status: "1" } };
      axios.get.mockResolvedValue(axiosResponse);
    });

    beforeEach(() => {
      mockTxEvent = {
        filterLog: jest.fn(),
        filterFunction: jest.fn(),
        hash: "hash2",
        timestamp: 10000,
        from: spender,
      };
      mockTxEvent.filterLog.mockReset();
      mockTxEvent.filterFunction.mockReset();
      mockGetCode.mockReset();
      mockProviderGetCode.mockClear();
      mockProviderGetTransactionCount.mockClear();
      mockProvider.getCode.mockReset();
      mockProvider.getTransactionCount.mockClear();
      mockBalanceOf.mockReset();

      Object.keys(getApprovals()).forEach((s) => delete getApprovals()[s]);
      Object.keys(getERC721Approvals()).forEach((s) => delete getERC721Approvals()[s]);
      Object.keys(getERC20Approvals()).forEach((s) => delete getERC20Approvals()[s]);
      Object.keys(getPermissions()).forEach((s) => delete getPermissions()[s]);
      Object.keys(getTransfers()).forEach((s) => delete getTransfers()[s]);
      getCachedAddresses().clear();
      handleTransaction = provideHandleTransaction(mockProvider);
    });

    it("should return empty findings if there are no Approval and Transfer events and no permit functions", async () => {
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
      expect(mockGetCode).toHaveBeenCalledTimes(0);
    });

    it("should return findings if there is a EIP-2612's permit function call", async () => {
      mockTxEvent.filterFunction.mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
          },
          addresses: [asset],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return findings if there is a DAI-like permit function call", async () => {
      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got permission for ERC-20 tokens",
          description: `${spender} gave permission to ${spender} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-PERMIT",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            msgSender: spender,
            owner: owner1,
            spender,
          },
          addresses: [asset],
        }),
      ]);
      expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(6);
      expect(mockTxEvent.filterFunction).toHaveBeenCalledTimes(2);
    });

    it("should return findings if there is a high number of ERC1155 ApprovalForAll events", async () => {
      const tempTxEvent0 = {
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[0]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash0",
        timestamp: 0,
        from: spender,
      };
      mockProvider.getCode.mockReturnValueOnce("0x").mockReturnValueOnce("0x").mockReturnValueOnce("0x992eb2c2d699");
      mockProvider.getTransactionCount.mockReturnValue(1);
      await handleTransaction(tempTxEvent0);

      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);

      const tempTxEvent1 = {
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([mockApprovalForAllEvent[1]]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash1",
        timestamp: 1000,
        from: spender,
      };
      mockProvider.getCode.mockReturnValueOnce("0x").mockReturnValueOnce("0x992eb2c2d699");
      mockProvider.getTransactionCount.mockReturnValue(1);
      await handleTransaction(tempTxEvent1);

      expect(mockProvider.getCode).toHaveBeenCalledTimes(5);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValueOnce("0x").mockReturnValueOnce("0x992eb2c2d699");
      mockProvider.getTransactionCount.mockReturnValue(1);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(5);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-1155 tokens",
          description: `${spender} obtained transfer approval for all ERC-1155 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 ApprovalForAll events", async () => {
      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        mockProvider.getTransactionCount.mockReturnValue(1);
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      mockProvider.getTransactionCount.mockReturnValue(1);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(5);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Account got approval for all ERC-721 tokens",
          description: `${spender} obtained transfer approval for all ERC-721 tokens from ${owner3}`,
          alertId: "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            spender,
            owner: owner3,
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC20 Approval events", async () => {
      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");
      expect(mockProvider.getCode).toHaveBeenCalledTimes(3);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High number of accounts granted approvals for ERC-20 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-20 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC721 Approval events", async () => {
      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValue([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValue([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([mockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);

      const findings = await handleTransaction(mockTxEvent);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "High number of accounts granted approvals for ERC-721 tokens",
          description: `${spender} obtained transfer approval for 1 ERC-721 tokens by 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS",
          severity: FindingSeverity.Low,
          type: FindingType.Suspicious,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-20 Transfer events and the balance is completely drained", async () => {
      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[2]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should not return findings if there is a high number of ERC-20 Transfer events but the balance is not completely drained", async () => {
      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([mockApprovalERC20Events2[i]]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([mockTransferEvents2[i]]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };
        mockBalanceOf
          .mockResolvedValue(ethers.BigNumber.from("100000000000000"))
          .mockResolvedValue(ethers.BigNumber.from("100000000000000")); // not drained
        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events2[2]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents2[2]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from("100000000000000")); // not drained
      expect(mockProvider.getCode).toHaveBeenCalledTimes(5);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("should return findings if there is a high number of ERC-721 Transfer events", async () => {
      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([mockApprovalERC721Events[i]]) // ERC721 approvals
            .mockReturnValueOnce([]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([mockTransferERC721Events[i]]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([mockApprovalERC721Events[2]]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([mockTransferERC721Events[2]]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      expect(mockProvider.getCode).toHaveBeenCalledTimes(5);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferSingle events and the balance is completely drained", async () => {
      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferSingleEvents[i]]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferSingleEvents[2]]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(8);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there is a high number of ERC-1155 TransferBatch events and the balance is completely drained", async () => {
      // Create the Approval events first
      for (let i = 0; i < 3; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 1000 * i,
          from: spender,
        };
        mockProvider.getCode.mockReturnValue("0x");

        await handleTransaction(tempTxEvent);
      }

      for (let i = 0; i < 2; i++) {
        const tempTxEvent = {
          filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([]),
          filterLog: jest
            .fn()
            .mockReturnValueOnce([]) // ERC20 approvals
            .mockReturnValueOnce([]) // ERC721 approvals
            .mockReturnValueOnce([mockApprovalForAllEvent[i]]) // ApprovalForAll
            .mockReturnValueOnce([]) // ERC20 transfers
            .mockReturnValueOnce([]) // ERC721 transfers
            .mockReturnValueOnce([mockTransferBatchEvents[i]]), // ERC1155 transfers
          hash: `hash${i}`,
          timestamp: 3000 + 1000 * i,
          from: spender,
        };

        await handleTransaction(tempTxEvent);
      }

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([mockApprovalForAllEvent[2]]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([mockTransferBatchEvents[2]]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValue(ethers.BigNumber.from(0));
      expect(mockProvider.getCode).toHaveBeenCalledTimes(8);

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously approved assets transferred",
          description: `${spender} transferred 1 assets from 3 accounts over period of 1 days.`,
          alertId: "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            firstTxHash: "hash0",
            lastTxHash: "hash2",
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if there's a transfer following an EIP-2612's permit function call", async () => {
      const tempTxEvent = {
        filterFunction: jest.fn().mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");

      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
          },
          addresses: asset,
        }),
      ]);
    });

    it("should return findings if there's a transfer following a DAI-like permit function call", async () => {
      const tempTxEvent = {
        filterFunction: jest.fn().mockReturnValueOnce([]).mockReturnValueOnce([mockDAILikePermitFunctionCall]),
        filterLog: jest
          .fn()
          .mockReturnValueOnce([]) // ERC20 approvals
          .mockReturnValueOnce([]) // ERC721 approvals
          .mockReturnValueOnce([]) // ApprovalForAll
          .mockReturnValueOnce([]) // ERC20 transfers
          .mockReturnValueOnce([]) // ERC721 transfers
          .mockReturnValueOnce([]), // ERC1155 transfers
        hash: "hash33",
        timestamp: 1001,
        from: spender,
      };
      mockProvider.getCode.mockReturnValue("0x");

      await handleTransaction(tempTxEvent);

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(0));

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Previously permitted assets transferred",
          description: `${spender} transferred ${mockTransferEvents[0].args.value} tokens from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-PERMITTED-ERC20-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
            spender: spender,
          },
          addresses: asset,
        }),
      ]);
    });

    it("should return findings if a scam address has been given permission", async () => {
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [createAddress("0x5050")] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      await handleBlock(mockBlockEvent);

      const mockPermitFunctionCall = {
        address: asset,
        args: {
          owner: owner1,
          spender: createAddress("0x5050"),
          deadline: 9359543534435,
          value: ethers.BigNumber.from(210),
        },
      };

      mockTxEvent.filterFunction.mockReturnValueOnce([mockPermitFunctionCall]).mockReturnValueOnce([]);
      mockTxEvent.filterLog.mockReturnValue([]);
      mockProvider.getCode.mockReturnValue("0x");

      const axiosResponse2 = { data: { "www.scamDomain.com": [createAddress("0x5050")] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address was involved in an ERC-20 permission",
          description: `${spender} gave permission to ${createAddress("0x5050")} for ${owner1}'s ERC-20 tokens`,
          alertId: "ICE-PHISHING-ERC20-SCAM-PERMIT",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamAddresses: [createAddress("0x5050")],
            scamDomains: ["www.scamDomain.com"],
            msgSender: spender,
            spender: createAddress("0x5050"),
            owner: owner1,
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if a scam address has been given approval", async () => {
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [spender] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      await handleBlock(mockBlockEvent);

      mockTxEvent.filterLog
        .mockReturnValueOnce([mockApprovalERC20Events[0]]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");

      const axiosResponse2 = { data: { "www.scamDomain.com": [spender] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address got approval to spend assets",
          description: `Scam address ${spender} got approval for ${owner1}'s assets`,
          alertId: "ICE-PHISHING-SCAM-APPROVAL",
          severity: FindingSeverity.High,
          type: FindingType.Suspicious,
          metadata: {
            scamDomains: ["www.scamDomain.com"],
            scamSpender: spender,
            owner: owner1,
          },
          addresses: [asset],
        }),
      ]);
    });

    it("should return findings if a scam address is involved in a transfer", async () => {
      const mockBlockEvent = { block: { timestamp: 1000 } };
      const axiosResponse = { data: [spender] };
      axios.get.mockResolvedValueOnce(axiosResponse);
      await handleBlock(mockBlockEvent);

      mockTxEvent.filterLog
        .mockReturnValueOnce([]) // ERC20 approvals
        .mockReturnValueOnce([]) // ERC721 approvals
        .mockReturnValueOnce([]) // ApprovalForAll
        .mockReturnValueOnce([mockTransferEvents[0]]) // ERC20 transfers
        .mockReturnValueOnce([]) // ERC721 transfers
        .mockReturnValueOnce([]); // ERC1155 transfers

      mockTxEvent.filterFunction.mockReturnValueOnce([]).mockReturnValueOnce([]);
      mockProvider.getCode.mockReturnValue("0x");

      const axiosResponse2 = { data: { "www.scamDomain.com": [spender] } };
      axios.get.mockResolvedValueOnce(axiosResponse2);
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Known scam address was involved in an asset transfer",
          description: `${spender} transferred assets from ${owner1} to ${mockTransferEvents[0].args.to}`,
          alertId: "ICE-PHISHING-SCAM-TRANSFER",
          severity: FindingSeverity.Critical,
          type: FindingType.Exploit,
          metadata: {
            scamAddresses: [spender],
            scamDomains: ["www.scamDomain.com"],
            msgSender: spender,
            owner: owner1,
            receiver: mockTransferEvents[0].args.to,
          },
          addresses: [asset],
        }),
      ]);
    });
  });

  describe("handleBlock", () => {
    const timePeriod = 2 * timePeriodDays * 24 * 60 * 60;

    beforeEach(() => {
      resetLastTimestamp();
      const axiosResponse = { data: { status: "1" } };
      axios.get.mockResolvedValue(axiosResponse);
      Object.keys(getApprovals()).forEach((s) => delete getApprovals()[s]);
      Object.keys(getERC20Approvals()).forEach((s) => delete getERC20Approvals()[s]);
      Object.keys(getERC721Approvals()).forEach((s) => delete getERC721Approvals()[s]);
      Object.keys(getERC721ApprovalsForAll()).forEach((s) => delete getERC721ApprovalsForAll()[s]);
      Object.keys(getERC1155ApprovalsForAll()).forEach((s) => delete getERC1155ApprovalsForAll()[s]);
      Object.keys(getPermissions()).forEach((s) => delete getPermissions()[s]);
      Object.keys(getTransfers()).forEach((s) => delete getTransfers()[s]);
    });

    it("should do nothing if enough time has not passed", async () => {
      const mockBlockEvent = { block: { timestamp: 1000 } };
      getApprovals()[spender] = [{ timestamp: 1000 }];
      getERC20Approvals()[spender] = [{ timestamp: 1000 }];
      getERC721Approvals()[spender] = [{ timestamp: 1000 }];
      getERC721ApprovalsForAll()[spender] = [{ timestamp: 1000 }];
      getERC1155ApprovalsForAll()[spender] = [{ timestamp: 1000 }];
      getPermissions()[spender] = [{ deadline: 10 }];
      getTransfers()[spender] = [{ timestamp: 1000 }];
      await handleBlock(mockBlockEvent);

      expect(Object.keys(getApprovals()).length).toStrictEqual(1);
      expect(Object.keys(getERC20Approvals()).length).toStrictEqual(1);
      expect(Object.keys(getERC721Approvals()).length).toStrictEqual(1);
      expect(Object.keys(getERC721ApprovalsForAll()).length).toStrictEqual(1);
      expect(Object.keys(getERC1155ApprovalsForAll()).length).toStrictEqual(1);
      expect(Object.keys(getPermissions()).length).toStrictEqual(1);
      expect(Object.keys(getTransfers()).length).toStrictEqual(1);
    });

    it("should not delete the entry if it was updated recently/permission deadline has not passed", async () => {
      const mockBlockEvent = { block: { timestamp: timePeriod } };
      getApprovals()[spender] = [{ timestamp: timePeriod }];
      getERC20Approvals()[spender] = [{ timestamp: timePeriod }];
      getERC721Approvals()[spender] = [{ timestamp: timePeriod }];
      getERC721ApprovalsForAll()[spender] = [{ timestamp: timePeriod }];
      getERC1155ApprovalsForAll()[spender] = [{ timestamp: timePeriod }];
      getPermissions()[spender] = [{ deadline: 5184001 }];
      getTransfers()[spender] = [{ timestamp: timePeriod }];
      await handleBlock(mockBlockEvent);

      expect(Object.keys(getApprovals()).length).toStrictEqual(1);
      expect(Object.keys(getERC20Approvals()).length).toStrictEqual(1);
      expect(Object.keys(getERC721Approvals()).length).toStrictEqual(1);
      expect(Object.keys(getERC721ApprovalsForAll()).length).toStrictEqual(1);
      expect(Object.keys(getERC1155ApprovalsForAll()).length).toStrictEqual(1);
      expect(Object.keys(getPermissions()).length).toStrictEqual(1);
      expect(Object.keys(getTransfers()).length).toStrictEqual(1);
    });

    it("should delete the entry if it was not updated recently", async () => {
      const mockBlockEvent = { block: { timestamp: timePeriod } };
      getApprovals()[spender] = [{ timestamp: 1000 }];
      getERC20Approvals()[spender] = [{ timestamp: 1000 }];
      getERC721Approvals()[spender] = [{ timestamp: 1000 }];
      getERC721ApprovalsForAll()[spender] = [{ timestamp: 1000 }];
      getERC1155ApprovalsForAll()[spender] = [{ timestamp: 1000 }];
      getPermissions()[spender] = [{ deadline: 1000 }];
      getTransfers()[spender] = [{ timestamp: 1000 }];
      await handleBlock(mockBlockEvent);

      expect(Object.keys(getApprovals()).length).toStrictEqual(0);
      expect(Object.keys(getERC20Approvals()).length).toStrictEqual(0);
      expect(Object.keys(getERC721Approvals()).length).toStrictEqual(0);
      expect(Object.keys(getERC721ApprovalsForAll()).length).toStrictEqual(0);
      expect(Object.keys(getERC1155ApprovalsForAll()).length).toStrictEqual(0);
      expect(Object.keys(getPermissions()).length).toStrictEqual(0);
      expect(Object.keys(getTransfers()).length).toStrictEqual(0);
    });
  });
});
