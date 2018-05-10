const scrypt = require('scrypt');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const { entropyToMnemonic, mnemonicToEntropy } = require('./mnemonic');

const paramsPerVersion = [
  { "N": 1024, "r": 8, "p": 16 },
  { "N": 1024, "r": 80, "p": 16 },
  { "N": 1024, "r": 1000, "p": 16 },
];

(async () => {
  const salt = 'hello';
  // const { privKey, mnemonic } = await generate(0, salt);
  const mnemonic = 'illegal picture write warfare title owner truck scale';
  const privKey = await generateFromMnemonic(mnemonic, salt);
  var m = bitcoin.HDNode.fromSeedBuffer(privKey);
  // console.log(privKey.toString('hex'));
  console.log('xpriv', m.keyPair.toWIF());
  console.log('xpub', m.neutered().toBase58());
  console.log('mnemonic', mnemonic);
  const child = m.derivePath("m/44'/0'/0'/0")
  for (let i = 0; i < 10; i++) {
    console.log(`address ${i + 1}`, child.derive(i).getAddress());
  }
})();

async function generate(version, salt) {
  const versionBuffer = Buffer.from([version]);
  const entropy = crypto.randomBytes(10);
  const mnemonic = entropyToMnemonic(entropy, versionBuffer);
  const privKey = await getPrivateKey(entropy, salt, version);
  return { privKey, mnemonic };
}

async function generateFromMnemonic(mnemonic, salt) {
  const { entropy, version: versionByte } = mnemonicToEntropy(mnemonic);
  const version = versionByte[0];
  const privKey = await getPrivateKey(entropy, salt, version);
  return privKey;
}

async function getPrivateKey(password, salt, version) {
  return new Promise((resolve, reject) => {
    scrypt.hash(password, getScryptParams(version), 32, salt, function (err, result) {
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
};