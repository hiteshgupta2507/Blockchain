const HDWalletProvider = require('truffle-hdwallet-provider');
// const infura = 'https://rinkeby.infura.io/v3/1a7e4280e0884cd1a9384a0e05596da9';
const mnemonic = "square captain lawn report jar achieve hen spread olympic debate sphere melody";

module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*" // Match any network id
    },
    rinkeby: {
      provider: () => new HDWalletProvider(mnemonic, "https://rinkeby.infura.io/v3/1a7e4280e0884cd1a9384a0e05596da9"),
      network_id: 4,
      gas: 4500000,
      gasPrice: 10000000000
    }
  },
  mocha: {
    timeout: 200000
  },

  // Configure your compilers
  compilers: {
    solc: {
      //      version: "0.5.0",    // Fetch exact version from solc-bin (default: truffle's version)
      // docker: true,        // Use "0.5.1" you've installed locally with docker (default: false)
      // settings: {          // See the solidity docs for advice about optimization and evmVersion
      //  optimizer: {
      //    enabled: false,
      //    runs: 200
      //  },
      //  evmVersion: "byzantium"
      // }
    }
  }
};