const mockEthcallProviderAll = jest.fn();
const mockBalanceOf = jest.fn();

const { FindingType, FindingSeverity, Finding, ethers } = require("forta-agent");
const { hashCode } = require("./helper");
const { createAddress } = require("forta-agent-tools");
const { handleTransaction, handleBlock, getTransfersObj } = require("./agent");

const asset = createAddress("0x01");
const address1 = createAddress("0x02");
const address2 = createAddress("0x03");
const address3 = createAddress("0x04");
const address4 = createAddress("0x05");
const address5 = createAddress("0x06");

const hashCode1 = hashCode(address1, asset);
const hashCode2 = hashCode(address2, asset);
const hashCode3 = hashCode(address3, asset);

const symbol = "TOKEN";

jest.mock("forta-agent-tools", () => {
  const original = jest.requireActual("forta-agent-tools");
  return {
    ...original,
    MulticallProvider: jest.fn().mockImplementation(() => ({
      all: mockEthcallProviderAll,
    })),
  };
});

jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    getEthersProvider: jest.fn().mockImplementation(() => ({
      _isSigner: true,
      getCode: () => "0x000000",
    })),
    ethers: {
      ...original.ethers,
      Contract: jest.fn().mockImplementation(() => ({
        balanceOf: mockBalanceOf,
        symbol: () => symbol,
      })),
    },
  };
});

describe("Asset drained bot test suite", () => {
  describe("handleTransaction", () => {
    const mockTxEvent = {
      filterLog: jest.fn(),
      hash: ethers.utils.formatBytes32String("0x352352"),
      from: address4,
      traces: [],
    };

    beforeEach(() => {
      mockTxEvent.filterLog.mockReset();
      Object.keys(getTransfersObj()).forEach((key) => delete getTransfersObj()[key]);
    });

    it("should do nothing if there are no transfers", async () => {
      mockTxEvent.filterLog.mockReturnValueOnce([]);
      await handleTransaction(mockTxEvent);
      expect(Object.keys(getTransfersObj()).length).toStrictEqual(0);
    });

    it("should add transfers in the object if there are transfers", async () => {
      const mockTransferEvent1 = {
        address: asset,
        args: {
          from: address1,
          to: address2,
          value: ethers.BigNumber.from(10),
        },
      };
      const mockTransferEvent2 = {
        address: asset,
        args: {
          from: address2,
          to: address3,
          value: ethers.BigNumber.from(10),
        },
      };
      mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1, mockTransferEvent2]);

      await handleTransaction(mockTxEvent);
      expect(Object.keys(getTransfersObj()).length).toStrictEqual(3);
      expect(getTransfersObj()[hashCode1]).toStrictEqual({
        asset,
        address: address1,
        value: ethers.BigNumber.from(-10),
        txs: {
          "0x0000000000000000000000000000000000000003": [
            { hash: ethers.utils.formatBytes32String("0x352352"), txFrom: address4 },
          ],
        },
      });
      expect(getTransfersObj()[hashCode2]).toStrictEqual({
        asset,
        address: address2,
        value: ethers.BigNumber.from(0),
        txs: {
          "0x0000000000000000000000000000000000000004": [
            { hash: ethers.utils.formatBytes32String("0x352352"), txFrom: address4 },
          ],
        },
      });
      expect(getTransfersObj()[hashCode3]).toStrictEqual({
        asset,
        address: address3,
        value: ethers.BigNumber.from(10),
        txs: {},
      });
    });
  });

  describe("handleBlock", () => {
    const mockTxEvent = {
      filterLog: jest.fn(),
      hash: ethers.utils.formatBytes32String("0x2352352"),
      from: address4,
      traces: [],
    };
    const mockTxEvent2 = {
      filterLog: jest.fn(),
      hash: ethers.utils.formatBytes32String("0x442352352"),
      from: address5,
      traces: [],
    };
    const mockBlockEvent = { blockNumber: 10_000 };

    beforeEach(() => {
      mockTxEvent.filterLog.mockReset();
      mockTxEvent2.filterLog.mockReset();
      Object.keys(getTransfersObj()).forEach((key) => delete getTransfersObj()[key]);
    });

    it("should not alert if there are no transfers", async () => {
      mockTxEvent.filterLog.mockReturnValueOnce([]);
      await handleTransaction(mockTxEvent);
      const findings = await handleBlock(mockBlockEvent);
      expect(findings).toStrictEqual([]);
    });

    it("should alert if there are contracts with fully drained assets", async () => {
      const mockTransferEvent1 = {
        address: asset,
        args: {
          from: address1,
          to: address2,
          value: ethers.BigNumber.from(10),
        },
      };
      mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1]);
      mockEthcallProviderAll.mockResolvedValueOnce([true, [ethers.BigNumber.from(0)]]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(10)); // Mock balance 10 mins ago

      await handleTransaction(mockTxEvent);
      const findings = await handleBlock(mockBlockEvent);
      expect(mockEthcallProviderAll).toHaveBeenCalledTimes(1);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Asset drained",
          description: `All ${symbol} tokens were drained from ${address1}`,
          alertId: "ASSET-DRAINED",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            contract: address1,
            asset,
            txFroms: [address4],
            txHashes: [ethers.utils.formatBytes32String("0x2352352")],
            blockNumber: 9999,
          },
          addresses: [address2],
        }),
      ]);
    });

    it("should alert if there are contracts with assets fully drained in more than one tx in the same block", async () => {
      const mockTransferEvent1 = {
        address: asset,
        args: {
          from: address1,
          to: address2,
          value: ethers.BigNumber.from(8),
        },
      };
      const mockTransferEvent2 = {
        address: asset,
        args: {
          from: address1,
          to: address3,
          value: ethers.BigNumber.from(2),
        },
      };

      mockTxEvent.filterLog.mockReturnValueOnce([mockTransferEvent1]);
      mockTxEvent2.filterLog.mockReturnValueOnce([mockTransferEvent2]);
      mockEthcallProviderAll.mockResolvedValueOnce([true, [ethers.BigNumber.from(0)]]);
      mockBalanceOf.mockResolvedValueOnce(ethers.BigNumber.from(10)); // Mock balance 10 mins ago

      await handleTransaction(mockTxEvent);
      await handleTransaction(mockTxEvent2);
      const findings = await handleBlock(mockBlockEvent);
      expect(mockEthcallProviderAll).toHaveBeenCalledTimes(2);
      expect(findings).toStrictEqual([
        Finding.fromObject({
          name: "Asset drained",
          description: `All ${symbol} tokens were drained from ${address1}`,
          alertId: "ASSET-DRAINED",
          severity: FindingSeverity.High,
          type: FindingType.Exploit,
          metadata: {
            contract: address1,
            asset,
            txFroms: [address4, address5],
            txHashes: [ethers.utils.formatBytes32String("0x2352352"), ethers.utils.formatBytes32String("0x442352352")],
            blockNumber: 9999,
          },
          addresses: [address2, address3],
        }),
      ]);
    });
  });
});
