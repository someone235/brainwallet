
let bitcoin = require('bitcoinjs-lib')


function toBech32Add(compressedPubKeyAddress){

//TEST:
//var compressedPubKeyAddress = '032a707c71d262046dbd1cfa2254b1c70ae179e1311ec37225e07fba343d741a44';
//
if (!Buffer.isBuffer(compressedPubKeyAddress)) compressedPubKeyAddress = Buffer.from(compressedPubKeyAddress, 'hex')
var bech32 = bitcoin.networks.bech32;
    var keyPairs = [compressedPubKeyAddress].map(function (q) { return bitcoin.ECPair.fromPublicKeyBuffer(Buffer.from(q, 'hex'),bech32) }); 
var keyPair = keyPairs[0];

    var pubKey = keyPair.getPublicKeyBuffer()

    var scriptPubKey = bitcoin.script.witnessPubKeyHash.output.encode(bitcoin.crypto.hash160(pubKey))
    var address = bitcoin.address.fromOutputScript(scriptPubKey)


    console.log(address)

}

module.exports = {
  toBech32Add: toBech32Add
  }


  //toBech32Add('032a707c71d262046dbd1cfa2254b1c70ae179e1311ec37225e07fba343d741a44')