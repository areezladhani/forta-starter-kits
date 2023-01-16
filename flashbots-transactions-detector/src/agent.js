const {
  Finding,
  FindingSeverity,
  FindingType,
  getTransactionReceipt,
  fetchJwt,
  ethers,
  provider,
  LabelType,
  EntityType,
  getEthersProvider,
} = require("forta-agent");
const { default: axios } = require("axios");
const { fetch, Headers } = require("node-fetch");
const { existsSync, readFileSync, writeFileSync } = require("fs");
const { getAlerts } = require("forta-agent");
const { AlertsResponse } = require("forta-agent/dist/sdk/graphql/forta");
const LRU = require("lru-cache");

const cachedFindings = new LRU({ max: 100_000 });
let findingsCounter = 0;

const flashbotsUrl = "https://blocks.flashbots.net/v1/blocks?limit=10";
let lastBlockNumber = 0;
let findingsLen = 0;

//
const TOTAL_FLASHBOTS_TXNS_KEY = "nm-flashbots-bot-key";
const TOTAL_TXNS_KEY = "nm-flashbots-bot-total-txns-key";

let totalFlashbotsTxns, totalTxns;
let MostRecTxHash;

function provideInitialize(provider, botsDep) {
  return async function initialize() {
    totalFlashbotsTxns = await load(TOTAL_FLASHBOTS_TXNS_KEY);

    //if we DON’T have access to the DB from Forta
    // we first check if the totalFlashbotsTxns is null
    // if yes then this is the first time we are running the bot and have to populate the db
    // to get the totalFlashbotTxns we use the getAlerts method and iterate through all the pages
    if (totalFlashbotsTxns == null) {
      totalFlashbotsTxns = 7; // temp number while testing

      /*
      //use the getAlerts method
      let hasNext = true;
      let startingCursor = undefined;
      while (hasNext) {
        const results = await getAlerts({
          botIds: ["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5"],
        });
        hasNext = results.pageInfo.hasNextPage;
        startingCursor = results.pageInfo.endCursor;

        totalFlashbotsTxns += results.alerts.length;
        console.log(`alerts in page: ${results.alerts.length} `);
        console.log(`totalFlashbotsTxns: ${totalFlashbotsTxns} `);
       
      }
       */
    }

    totalTxns = await load(TOTAL_TXNS_KEY);

    const currBlock = await provider.getBlockNumber();

    //if we DON’T have access to the DB from Forta
    // we check if the totalTxns is null
    // if yes then this is the first time we are running the bot and have to populate the db
    // to get the totalTxns we use the getAlertsgetBlockWithTransactions and start from when the bot went live
    // all the way to the currentblock -1
    totalTxns = 10; // temp number while testing

    /*

      //use the getBlockWithTransactions method
      for (let x = botsDep; x <= currBlock; x++) {
        const getBlock = await provider.getBlockWithTransactions(x);
        const numOfTxs = getBlock["transactions"].length;
        console.log(`txs in block: ${numOfTxs} `);
        console.log(`totalTxns: ${totalTxns} `);
        totalTxns += numOfTxs;
      }
          */
  };
}

async function load(key) {
  if (process.env.hasOwnProperty("LOCAL_NODE")) {
    const token = await fetchJwt({});
    // Don't have documentation to check if this the header needed
    // Going off of Entity Cluster bot implementation
    const headers = new Headers({ Authorization: `Bearer ${token}` });
    const response = await fetch(`https://research.forta.network/database/bot/${key}`, { headers });
    // TODO: Confirm these are properties of `response`

    if (response.status === 200 && response.content.length > 0) {
      const bufferString = (await response.buffer()).toString();
      return JSON.parse(bufferString);
    } else {
      console.error(`${key} does not exist`);
    }
  } else {
    // Checking if it exists locally
    if (existsSync(key)) {
      const data = readFileSync(key);
      return JSON.parse(data.toString());
    } else {
      console.error(`file ${key} does not exist`);
    }
  }
}

async function persist(value, key) {
  const valueToPersist = Buffer.from(value.toString());
  if (process.env.hasOwnProperty("LOCAL_NODE")) {
    const token = await fetchJwt({});
    // Don't have documentation to check if this the header needed
    // Going off of Entity Cluster bot implementation
    const headers = new Headers({ Authorization: `Bearer ${token}` });
    const response = await fetch(`https://research.forta.network/database/bot/${key}`, {
      method: "POST",
      headers,
      body: valueToPersist,
    });
    return;
  } else {
    // Persist locally
    writeFileSync(key, valueToPersist);
    return;
  }
}

//
function provideHandleBlock(getTransactionReceipt) {
  return async function handleTransaction(blockEvent) {
    let result;
    try {
      result = await axios.get(flashbotsUrl);
    } catch (e) {
      console.log("Error:", e.code);
      return [];
    }

    const { blocks } = result.data;
    let y;
    while (y < 2) {
      if (cachedFindings.has(y)) {
        cachedFindings.delete(y);
      }
      y++;
    }

    /*
    if (blockEvent.blockNumber % 240 === 0) {
      console.log("hit target");
      persist(totalFlashbotsTxns, TOTAL_FLASHBOTS_TXNS_KEY);
      persist(totalTxns, TOTAL_TXNS_KEY);
    }
    */
    const numOfTxs = blockEvent.block.transactions.length;
    totalTxns += numOfTxs;

    // Get findings for every new flashbots block and combine them
    let findings = await Promise.all(
      blocks.map(async (block) => {
        const { transactions, block_number: blockNumber } = block;
        let currentBlockFindings;
        // Only process blocks that aren't processed
        if (blockNumber > lastBlockNumber) {
          /*
          const numOfTxs = blockEvent.block.transactions.length;
          totalTxns += numOfTxs;
          console.log(`txs in block = ${numOfTxs}`);
          const AnomScore = totalFlashbotsTxns / totalTxns;
          */

          //console.log(`tx: ${transactions.length}`);

          //console.log(`txs in block = ${numOfTxs}`);
          //const txsRoot = blockEvent.block.transactionsRoot;
          //console.log(`txs root = ${txsRoot}`);
          // Create finding for every flashbots transaction in the block
          currentBlockFindings = await Promise.all(
            transactions
              .filter((transaction) => transaction.bundle_type !== "mempool")
              .map(async (transaction) => {
                const { eoa_address: from, to_address: to, transaction_hash: hash } = transaction;

                // Use the tx logs to get the impacted contracts
                const { logs } = await getTransactionReceipt(hash);
                let addresses = logs.map((log) => log.address.toLowerCase());
                addresses = [...new Set(addresses)];
                totalFlashbotsTxns += 1;

                const AnomScore = totalFlashbotsTxns / totalTxns;
                //console.log(`anom score: ${AnomScore}`);
                //console.log(`totalFbTxns: ${totalFlashbotsTxns}`);
                //console.log(`totalTxns: ${totalTxns}`);
                //console.log(`blockNumber ${blockNumber}`);
                return Finding.fromObject({
                  name: "Flashbots transactions",
                  description: `${from} interacted with ${to} in a flashbots transaction`,
                  alertId: "FLASHBOTS-TRANSACTIONS",
                  severity: FindingSeverity.Low,
                  type: FindingType.Info,
                  addresses,
                  metadata: {
                    from,
                    to,
                    hash,
                    blockNumber,
                    AnomScore,
                  },
                  labels: [
                    {
                      entityType: EntityType.Address,
                      entity: "Flashbots transaction",
                      labelType: LabelType.Unknown, // Depends on profit amount
                      confidence: 1,
                      customValue: "",
                    },
                  ],
                });
              })
          );

          lastBlockNumber = blockNumber;
        }

        return currentBlockFindings;
      })
    );

    findings = findings.flat().filter((f) => !!f);
    findings.forEach((finding) => {
      cachedFindings.set(findingsCounter, finding);
      findingsCounter++;
    });

    let blfindings = [];
    let x;
    while (x < 2) {
      if (cachedFindings.has(x)) {
        blfindings.push(cachedFindings.get(x));
        //cachedFindings.delete(x);
      }

      x++;
    }

    return blfindings;
  };
}

/*
function provideHandleTransaction() {
  return async function handleTransaction(txEvent) {
    const findings = [];
    totalTxns += 1;

    console.log(txEvent.transaction.hash);
    console.log(txEvent.blockNumber);

    MostRecTxHash = "0x00a0ff958f99fabe8a6bde12304436ed6c43524d1ab12bced426abf3a507d939";

    const results = await getAlerts({
      botIds: ["0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5"],
      transactionHash: txEvent.transaction.hash,
    });
    if (results.alerts.length > 0) {
      console.log("new flash tx");
      totalFlashbotsTxns += 1;
    }

    const AnomScore = totalFlashbotsTxns / totalTxns;
    console.log(`total txns = ${totalTxns}`);
    console.log(`total f txns = ${totalFlashbotsTxns}`);
    console.log(`anomScore = ${AnomScore}`);
    console.log("done");
    return findings;
  };
}
*/

module.exports = {
  provideInitialize,
  initialize: provideInitialize(getEthersProvider(), 16330711),
  provideHandleBlock,
  handleBlock: provideHandleBlock(getTransactionReceipt),
  resetLastBlockNumber: () => {
    lastBlockNumber = 0;
  }, // Exported for unit tests
  /*
  provideHandleTransaction,
  handleTransaction: provideHandleTransaction(),
  */
};
