//var Buffer = require('safe-buffer').Buffer
//var createHash = require('create-hash')
//var pbkdf2 = require('pbkdf2').pbkdf2Sync
//var randomBytes = require('randombytes')

// use unorm until String.prototype.normalize gets better browser support
var unorm = require('unorm')


var ENGLISH_WORDLIST = require('./wordlists/english.json')

var DEFAULT_WORDLIST = ENGLISH_WORDLIST
var JAPANESE_WORDLIST = null;

var INVALID_MNEMONIC = 'Invalid mnemonic'
var INVALID_ENTROPY = 'Invalid entropy'
var INVALID_CHECKSUM = 'Invalid mnemonic checksum'

function lpad(str, padString, length) {
  while (str.length < length) str = padString + str
  return str
}

function binaryToByte(bin) {
  return parseInt(bin, 2)
}

function bytesToBinary(bytes) {
  return bytes.map(function (x) {
    return lpad(x.toString(2), '0', 8)
  }).join('')
}

function deriveChecksumBits(entropyBuffer) {
  var ENT = entropyBuffer.length * 8
  var CS = ENT / 32
  var hash = createHash('sha256').update(entropyBuffer).digest()

  return bytesToBinary([].slice.call(hash)).slice(0, CS)
}

function salt(password) {
  return 'mnemonic' + (password || '')
}

function mnemonicToSeed(mnemonic, password) {
  var mnemonicBuffer = Buffer.from(unorm.nfkd(mnemonic), 'utf8')
  var saltBuffer = Buffer.from(salt(unorm.nfkd(password)), 'utf8')

  return pbkdf2(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512')
}

function mnemonicToSeedHex(mnemonic, password) {
  return mnemonicToSeed(mnemonic, password).toString('hex')
}

function mnemonicToEntropy(mnemonic, wordlist) {
  wordlist = wordlist || DEFAULT_WORDLIST

  var words = unorm.nfkd(mnemonic).split(' ')
  if (words.length % 3 !== 0) throw new Error(INVALID_MNEMONIC)

  // convert word indices to 11 bit binary strings
  var bits = words.map(function (word) {
    var index = wordlist.indexOf(word)
    if (index === -1) throw new Error(INVALID_MNEMONIC)

    return lpad(index.toString(2), '0', 11)
  }).join('')

  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / 33) * 32
  var entropyBits = bits.slice(0, dividerIndex)
  var checksumBits = bits.slice(dividerIndex)

  // calculate the checksum and compare
  var entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte)
  if (entropyBytes.length < 16) throw new Error(INVALID_ENTROPY)
  if (entropyBytes.length > 32) throw new Error(INVALID_ENTROPY)
  if (entropyBytes.length % 4 !== 0) throw new Error(INVALID_ENTROPY)

  var entropy = Buffer.from(entropyBytes)
  var newChecksum = deriveChecksumBits(entropy)
  if (newChecksum !== checksumBits) throw new Error(INVALID_CHECKSUM)

  return entropy.toString('hex')
}


function mnemonicToEntropy2(mnemonic, wordlist) {
  wordlist = wordlist || DEFAULT_WORDLIST;

  var words = unorm.nfkd(mnemonic).split(' ')
  // if (words.length % 3 !== 0) throw new Error(INVALID_MNEMONIC)

  // convert word indices to 11 bit binary strings
  var bits = words.map(function (word) {
    var index = wordlist.indexOf(word)
    if (index === -1) throw new Error(INVALID_MNEMONIC)

    return lpad(index.toString(2), '0', 11)
  }).join('')

  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / 11) * 10
  var entropyBits = bits.slice(0, dividerIndex)
  var versionByte = bits.slice(dividerIndex)

  // calculate the checksum and compare
  var entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte)
  versionByte = versionByte.match(/(.{1,8})/g).map(binaryToByte)

  var entropy = Buffer.from(entropyBytes)
  var version = Buffer.from(versionByte)
  //TODO: output both version and entropy
  return { entropy, version };
  //return {entropy.toString('hex'),version.toString('hex')}
}


function entropyToMnemonic(entropy, wordlist) {
  if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex')
  wordlist = wordlist || DEFAULT_WORDLIST

  // 128 <= ENT <= 256
  if (entropy.length < 16) throw new TypeError(INVALID_ENTROPY)
  if (entropy.length > 32) throw new TypeError(INVALID_ENTROPY)
  if (entropy.length % 4 !== 0) throw new TypeError(INVALID_ENTROPY)

  var entropyBits = bytesToBinary([].slice.call(entropy))
  var checksumBits = deriveChecksumBits(entropy)

  var bits = entropyBits + checksumBits
  var chunks = bits.match(/(.{1,11})/g)
  var words = chunks.map(function (binary) {
    var index = binaryToByte(binary)
    return wordlist[index]
  })

  return wordlist === JAPANESE_WORDLIST ? words.join('\u3000') : words.join(' ')
}

function entropyToMnemonic2(entropy,numOfWords, versionByte) {
  if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex')


  wordlist = DEFAULT_WORDLIST
  const requiredNumOfWords = 11* numOfWords-8;
 // console.log(requiredNumOfWords)
  //console.log(entropy.length*8 )
  if((entropy.length*8) < requiredNumOfWords) {throw new TypeError(INVALID_ENTROPY);}

  var tmp;

  while(entropy.length*8 > requiredNumOfWords)
  {
  //  console.log(entropy)
    tmp = entropy;
    entropy = entropy.slice(0,entropy.length-1);
   
  }
  //console.log(tmp.length*8)

  entropy = tmp;
  entropy = bytesToBinary([].slice.call(entropy));

  entropy = entropy.substring(0,entropy.length -(entropy.length) % requiredNumOfWords);



  //console.log(entropy.length -(entropy.length) % requiredNumOfWords)
  //if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex')
  if (!Buffer.isBuffer(versionByte)) versionByte = Buffer.from(versionByte, 'hex')
  //entropy = Buffer.concat([entropy, versionByte], entropy.length + versionByte.length);
  //TODO: add more restrictions to catch bad input
  //if (entropy.length > 32) throw new TypeError(INVALID_ENTROPY)
  // if (entropy.length % 4 !== 0) throw new TypeError(INVALID_ENTROPY)

  var versionBits = bytesToBinary([].slice.call(versionByte))
 // console.log(versionBits)
//console.log(entropyBits)
//console.log(binaryToByte(entropyBits).toString(16))
  var bits = entropy + versionBits;
 // console.log(bits)
  var chunks = bits.match(/(.{1,11})/g)
  var words = chunks.map(function (binary) {
    var index = binaryToByte(binary)
    return wordlist[index]
  })

  return wordlist === JAPANESE_WORDLIST ? words.join('\u3000') : words.join(' ')
}

function generateMnemonic(strength, rng, wordlist) {
  strength = strength || 128
  if (strength % 32 !== 0) throw new TypeError(INVALID_ENTROPY)
  rng = rng || randomBytes

  return entropyToMnemonic(rng(strength / 8), wordlist)
}

function validateMnemonic(mnemonic, wordlist) {
  try {
    mnemonicToEntropy(mnemonic, wordlist)
  } catch (e) {
    return false
  }

  return true
}

 console.log("dic: " + entropyToMnemonic2('aaaaaaaaaaaaaaaaa',5, '00'))
// console.log("entropy: " + mnemonicToEntropy2('primary fetch primary fetch primary fetch primary fetch'))
module.exports = {
  entropyToMnemonic: entropyToMnemonic2,
  mnemonicToEntropy: mnemonicToEntropy2,
}