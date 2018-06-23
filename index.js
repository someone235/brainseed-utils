const crypto = require('crypto');
const scrypt = require('scrypt');
const bip39 = require('bip39');

// use unorm until String.prototype.normalize gets better browser support
const unorm = require('unorm');
const WORD_BIT_SIZE = 11;


var ENGLISH_WORDLIST = require('./wordlists/english.json')

var DEFAULT_WORDLIST = ENGLISH_WORDLIST
var JAPANESE_WORDLIST = null;

var INVALID_MNEMONIC = 'Invalid mnemonic'
var INVALID_ENTROPY = 'Invalid entropy'

const paramsPerVersion = [
  // { "N": 32, "r": 8, "p": 1 },//100ms
  { "N": 1048576, "r": 8, "p": 1 },//4s
  { "N": 4194304, "r": 6, "p": 4 },//30s
  { "N": 4194304, "r": 600, "p": 4 },//1h
];

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

function validateMnemonic(mnemonic, wordlist) {
  try {
    mnemonicToEntropy(mnemonic, wordlist)
  } catch (e) {
    return false
  }

  return true
}


function mnemonicToEntropy(mnemonic, wordlist) {
  wordlist = wordlist || DEFAULT_WORDLIST;

  var words = unorm.nfkd(mnemonic).split(' ')
  // if (words.length % 3 !== 0) throw new Error(INVALID_MNEMONIC)

  // convert word indices to 11 bit binary strings
  var bits = words.map(function (word) {
    var index = wordlist.indexOf(word)
    if (index === -1) throw new Error(INVALID_MNEMONIC)

    return lpad(index.toString(2), '0', WORD_BIT_SIZE)
  }).join('')
  // split the binary string into ENT/CS
  var dividerIndex = Math.floor(bits.length / WORD_BIT_SIZE) * (WORD_BIT_SIZE - 1);
  var entropyBits = bits.slice(0, dividerIndex)
  var versionByte = bits.slice(dividerIndex)

  // calculate the checksum and compare
  var entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte)
  const version = versionByte.match(/(.{1,8})/g).map(binaryToByte)

  var entropy = Buffer.from(entropyBytes)
  return {
    entropy: entropy,
    version: version
  };
}


function entropyToMnemonic(entropy, numOfWords, version, wordlist = DEFAULT_WORDLIST) {
  if (!Buffer.isBuffer(entropy)) entropy = Buffer.from(entropy, 'hex')
  const versionByte = Buffer.from([version]);

  const requiredNumOfWords = WORD_BIT_SIZE * numOfWords - 8;
  if ((entropy.length * 8) < requiredNumOfWords) {
    throw new TypeError(INVALID_ENTROPY);
  }

  var tmp;
  tmp = entropy;
  while (entropy.length * 8 > requiredNumOfWords) {
    tmp = entropy;
    entropy = entropy.slice(0, entropy.length - 1);


  }

  entropy = tmp;
  entropy = bytesToBinary([].slice.call(entropy));

  entropy = entropy.substring(0, entropy.length - (entropy.length) % requiredNumOfWords);
  //entropy = Buffer.concat([entropy, versionByte], entropy.length + versionByte.length);
  //TODO: add more restrictions to catch bad input
  //if (entropy.length > 32) throw new TypeError(INVALID_ENTROPY)
  // if (entropy.length % 4 !== 0) throw new TypeError(INVALID_ENTROPY)

  var versionBits = bytesToBinary([].slice.call(versionByte))
  var bits = entropy + versionBits;
  const regexp = new RegExp(`(.{1,${WORD_BIT_SIZE}})`, 'g');
  var chunks = bits.match(regexp);
  var words = chunks.map(function (binary) {
    var index = binaryToByte(binary)
    return wordlist[index]
  })

  return wordlist === JAPANESE_WORDLIST ? words.join('\u3000') : words.join(' ')
}

function generateMnemonic(version, numberOfWords = 6, wordlist = DEFAULT_WORDLIST) {
  const entropy = crypto.randomBytes(Math.ceil(numberOfWords * WORD_BIT_SIZE / 8 - 1));
  return entropyToMnemonic(entropy, numberOfWords, version, wordlist);
}

async function mnemonicToSeed(mnemonic, salt, wordlist) {
  const bip39Mnemonic = await mnemonicToBip39Mnemonic(mnemonic, salt, wordlist);
  return bip39.mnemonicToSeed(bip39Mnemonic);
}

async function getScryptSeed(entropy, salt, version) {
  return new Promise((resolve, reject) => {
    scrypt.hash(entropy, getScryptParams(version), 32, salt, function (err, result) {
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

async function mnemonicToBip39Mnemonic(mnemonic, salt, wordlist) {
  const { entropy, version } = mnemonicToEntropy(mnemonic, wordlist);
  const scryptSeed = await getScryptSeed(entropy, salt, version);
  return bip39.entropyToMnemonic(scryptSeed);
}


module.exports = {
  mnemonicToBip39Mnemonic,
  generateMnemonic,
  entropyToMnemonic,
  mnemonicToEntropy,
  mnemonicToSeed,
  validateMnemonic
}