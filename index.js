const crypto = require('crypto')
const base58 = module.exports.base58 = require('bs58')

// hash a public key
// ripemd160(sha256(pk))
module.exports.pubkeyHash = (pubkey, encoding = 'hex') => {
  if (typeof pubkey === 'string') pubkey = new Buffer(pubkey, 'hex')
  if (!(pubkey instanceof Buffer)) throw new TypeError('"pubkey" must be a buffer')
  return crypto.createHash('ripemd160').update(
    crypto.createHash('sha256').update(pubkey).digest()
  ).digest(encoding)
}

// WIF (Wallet Import Format)

// https://en.bitcoin.it/wiki/Base58Check_encoding
// Prefix Table
//
// |----------|---------|------------------------------|
// | decimal  | leading | Use                          |
// | version  | symbol  |                              |
// |----------|---------|------------------------------|
// | 0        | 1       | Bitcoin pubkey hash          |
// | 5        | 3       | Bitcoin script hash          |
// | 21       | 4       | Bitcoin (compact) public key |
// | 52       | M or N  | Namecoin pubkey hash         |
// | 128      | 5       | Private key                  |
// | 111      | m or n  | Bitcoin testnet pubkey hash  |
// | 196      | 2       | Bitcoin testnet script hash  |
// |----------|---------|------------------------------|


module.exports.encodeWif = (pubkeyhash, version = '00', encoding = 'hex') => {
  if (typeof pubkeyhash === 'string') pubkeyhash = new Buffer(pubkeyhash, encoding)
  if (!(pubkeyhash instanceof Buffer)) throw new TypeError('"pubkeyhash" must be a buffer')
  if (!(version instanceof Buffer)) version = new Buffer(version, encoding)
  
  let hash = Buffer.concat([version, pubkeyhash])
  hash = crypto.createHash('sha256').update(hash).digest()
  hash = crypto.createHash('sha256').update(hash).digest()
  hash = Buffer.concat([version, pubkeyhash, hash.slice(0, 4)])
  return base58.encode(hash)
}

module.exports.decodeWif = (address, encoding) => {
  const buffer = new Buffer(base58.decode(address))

  let version = buffer.slice(0, 1)
  let pubkeyhash = buffer.slice(1, -4)
  let checksum = buffer.slice(-4)

  let doublehash = Buffer.concat([ version, pubkeyhash ])
  doublehash = crypto.createHash('sha256').update(doublehash).digest()
  doublehash = crypto.createHash('sha256').update(doublehash).digest()
  checksum.forEach((check, index) => {
    if (check !== doublehash[index]) {
      throw new Error('Invalid checksum')
    }
  })

  if (encoding) {
    version = version.toString(encoding)
    pubkeyhash = pubkeyhash.toString(encoding)
    checksum = checksum.toString(encoding)
    doublehash = doublehash.toString(encoding)
  }

  return { version, pubkeyhash, checksum, doublehash }
}



