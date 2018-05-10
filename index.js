const scrypt = require('scrypt');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const { entropyToMnemonic, mnemonicToEntropy } = require('./mnemonic');
const toBech32 = require('./toBech32');

// const paramsPerVersion = [
//   // { "N": 4194304, "r": 6, "p": 4 },
//   { "N": 1024, "r": 8, "p": 16 },
//   { "N": 1024, "r": 80, "p": 16 },
//   { "N": 1024, "r": 1000, "p": 16 },
// ];

const paramsPerVersion = [
  { "N": 32, "r": 8, "p": 1 },//100ms
  { "N": 1048576, "r": 8, "p": 1 },//4s
  { "N": 4194304, "r": 6, "p": 4 },//30s
];

(async () => {
  return;
  // console.log(await getPrivateKey(Buffer.from('231f29723597822810', 'hex'), 'hello', 1));
  const salt = 'hello';
  // const { privKey, mnemonic } = await generate(2, salt, 8);
  // console.log(mnemonic);
  const mnemonic = 'search butter because birth fitness thank gloom able';
  const privKey = await generateFromMnemonic(mnemonic, salt);
  console.log(privKey);
  // var m = bitcoin.HDNode.fromSeedBuffer(privKey);
  // // console.log(privKey.toString('hex'));
  // console.log('xpriv', m.keyPair.toWIF());
  // console.log('xpub', m.neutered().toBase58());
  // console.log('mnemonic', mnemonic);
  // const child = m.derivePath("m/84'/0'/0'/0")
  // for (let i = 0; i < 10; i++) {
  //   console.log(`address ${i + 1}`, child.derive(i).getAddress());
  // }
})();

async function generate(version, salt, numberOfWords = 6) {
  const versionBuffer = Buffer.from([version]);
  const entropy = crypto.randomBytes(Math.ceil(numberOfWords * 11 / 8 - 1));
  console.log('entropy', entropy.toString('hex'));
  console.log('salt', salt);
  const mnemonic = entropyToMnemonic(entropy, numberOfWords, versionBuffer);
  const privKey = await generateFromMnemonic(mnemonic, salt);
  // const privKey = await getPrivateKey(entropy, salt, version);
  return { privKey, mnemonic };
}

async function generateFromMnemonic(mnemonic, salt) {
  const { entropy, version: versionByte } = mnemonicToEntropy(mnemonic);
  const version = versionByte[0];
  console.log('entropy', entropy.toString('hex'));
  console.log('salt', salt);
  const privKey = await getPrivateKey(entropy, salt, version);
  return privKey;
}

async function getPrivateKey(password, salt, version) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    scrypt.hash(password, getScryptParams(version), 32, salt, function (err, result) {
      console.log('took', Date.now() - start);
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}


function getScryptParams(version) {
  return paramsPerVersion[version];
}

module.exports = {
  generate,
  generateFromMnemonic,
  toBech32,
};