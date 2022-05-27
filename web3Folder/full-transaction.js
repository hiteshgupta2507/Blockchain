/*##########################

CONFIGURATION
##########################*/

// -- Step 1: Set up the appropriate configuration
var Web3 = require('web3');
var EthereumTransaction = require('ethereumjs-tx').Transaction;
var url = 'HTTP://127.0.0.1:7545'; // 8454  if using ganacche cli
var web3 = new Web3(url);

// -- Step 2: Set the sending and receiving addresses for the transaction.
var sendingAddress = '0x447770950d6BB499926f94C72A183F6A184aCBfF';
var receivingAddress = '0x93aB2f8FE2a0619289383245Fd066eC9E1804467';

// -- Step 3: Check the balances of each address
web3.eth.getBalance(sendingAddress).then(console.log);
web3.eth.getBalance(receivingAddress).then(console.log);

/*##########################

CREATE A TRANSACTION
##########################*/

// -- Step 4: Set up the transaction using the transaction variables as shown

var rawTransaction = {
    nonce: web3.utils.toHex(1), // initially 0
    to: receivingAddress,
    gasPrice: web3.utils.toHex(20000000),
    gasLimit: web3.utils.toHex(30000),
    value: web3.utils.toHex(10 ** 18),
    data: web3.utils.toHex("")
}

// -- Step 5: View the raw transaction rawTransaction

// -- Step 6: Check the new account balances (they should be the same) 

web3.eth.getBalance(sendingAddress).then(console.log);
web3.eth.getBalance(receivingAddress).then(console.log);

// web3.eth.getBalance(sendingAddress).then(console.log(web3.utils.fromWei('1', 'ether')))
// web3.eth.getBalance(receivingAddress).then(console.log(web3.utils.fromWei('1', 'ether')))



// Note: They haven't changed because they need to be signed...

/*##########################

Sign the Transaction
##########################*/

// -- Step 7: Sign the transaction with the Hex value of the private key of the sender 
var privateKeySender = '795638e5b606328d963ed60e204b76615624afa90003da2fd3ede9e2bafadfb8';
var privateKeySenderHex = new Buffer.from(privateKeySender, 'hex');
var transaction = new EthereumTransaction(rawTransaction);
transaction.sign(privateKeySenderHex);

/*#########################################

Send the transaction to the network
#########################################*/

// -- Step 8: Send the serialized signed transaction to the Ethereum network.
var serializedTransaction = transaction.serialize();
web3.eth.sendSignedTransaction(serializedTransaction);


