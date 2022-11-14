const { FindingType, FindingSeverity, Finding, createTransactionEvent } = require("forta-agent");
const { provideHandleTranscation, provideInitialize } = require("./agent");

describe("TornadoCash contract interactions", () => {
  let initialize;
  const mockTxEvent = createTransactionEvent({});
  mockTxEvent.filterLog = jest.fn();
  const mockEthersProvider = { getCode: jest.fn(), getNetwork: jest.fn() };
  const handleTransaction = provideHandleTranscation(mockEthersProvider);

  beforeEach(async () => {
    mockTxEvent.filterLog.mockReset();
    initialize = provideInitialize(mockEthersProvider);
    mockEthersProvider.getNetwork.mockReturnValue({ chainId: 1 });
    await initialize();
  });

  it("returns empty findings if there are no contract interactions with an account that was funded from TornadoCash", async () => {
    mockTxEvent.filterLog.mockReturnValue([]);
    mockTxEvent.transaction = {};
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);

    expect(mockTxEvent.filterLog).toHaveBeenCalledTimes(1);
  });

  it("returns a finding if there is a contract interaction from an address that was funded from TornadoCash", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "0xb",
      data: "0x1234567Test",
    };
    mockEthersProvider.getCode.mockReturnValue("0x1234");
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([
      Finding.fromObject({
        name: "Tornado Cash funded account interacted with contract",
        description: `${mockTxEvent.transaction.from} interacted with contract ${mockTxEvent.to}`,
        alertId: "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION",
        severity: FindingSeverity.Low,
        type: FindingType.Suspicious,
      }),
    ]);
  });

  it("should not return a finding if the address that was funded from TornadoCash created a contract", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "", // contract creation
      data: "0x1234567Test",
    };
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);
  });

  it("should not return a finding if the address that was funded from TornadoCash interacted with a TornadoCash contract", async () => {
    mockTxEvent.filterLog.mockReturnValue([
      {
        args: {
          to: "0xa",
        },
      },
    ]);

    mockTxEvent.transaction = {
      from: "0xa",
      to: "0xbB93e510BbCD0B7beb5A853875f9eC60275CF498", // Ethereum 10 WBTC TC contract
      data: "0x1234567Test",
    };
    mockEthersProvider.getCode.mockReturnValue("0x1234");
    const findings = await handleTransaction(mockTxEvent);

    expect(findings).toStrictEqual([]);
  });
});
