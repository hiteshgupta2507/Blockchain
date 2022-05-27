var Web3 = require('web3');

var url = 'HTTP://127.0.0.1:7545'; // 8454  if using ganacche cli

var web3 = new Web3(url)

web3.eth.getTransactionCount('0x447770950d6BB499926f94C72A183F6A184aCBfF').then(console.log);