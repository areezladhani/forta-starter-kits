const aaveV3FlashloanSig =
  "event FlashLoan(address indexed target, address initiator, address indexed asset, uint256 amount, uint8 interestRateMode, uint256 premium, uint16 indexed referralCode)";

module.exports = {
  getAaveV3Flashloan: (txEvent) => {
    const flashloans = [];
    const events = txEvent.filterLog(aaveV3FlashloanSig);

    events.forEach((event) => {
      const { asset, amount, target } = event.args;
      flashloans.push({
        asset: asset.toLowerCase(),
        amount,
        account: target.toLowerCase(),
      });
    });
    return flashloans;
  },
};
