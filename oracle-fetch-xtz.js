require('dotenv').config();
const superagent = require('superagent');
const crypto = require('crypto');
const base58Check = require('bs58check')
const EC = require('elliptic').ec;
const blakejs = require('blakejs')

const key_id = process.env.API_KEY_ID;
const secret = process.env.API_SECRET;
const passphrase = process.env.API_PASSPHRASE;

const apiURI = 'https://api.pro.coinbase.com';

// Coinbase signer public key in base58 format
const publicKeyBase58 = "sppk7bkCcE4TZwnqqR7JAKJBybJ2XTCbKZu11ESTvvZQYtv3HGiiffN"
// False use case to test invalid signature
const messageFalse = "05070701000000074254432d555344070700808a97ef0b070700a0b39eef0b070700a0daefec47070700b097e0ee4707070090beeeec4707070090b79aed4700938ec106"
const signatureFalse = "spsig1cLwzXQEprTYcS9uLSRA8hqC1ZmJkayrbuDyaM31zHes8Jt2QRceJQcTFdjfAqQxYg82qg1GHavgzKHLZ4bxsyQokRxNNu"

var timestamp = Date.now() / 1000;
var requestPath = '/oracle/xtz';

var method = 'GET';

// create the prehash string by concatenating required parts
var what = timestamp + method + requestPath;

// decode the base64 secret
var key = Buffer(secret, 'base64');

// create a sha256 hmac with the secret
var hmac = crypto.createHmac('sha256', key);

// sign the require message with the hmac
// and finally base64 encode the result
var signature = hmac.update(what).digest('base64');

superagent
  .get(apiURI + requestPath)
  .set('CB-ACCESS-KEY', key_id)
  .set('CB-ACCESS-SIGN', signature)
  .set('CB-ACCESS-TIMESTAMP', timestamp)
  .set('CB-ACCESS-PASSPHRASE', passphrase)
  .set('User-Agent', 'abc')
  .set('accept', 'json')
  .end((err, res) => {
    if (err) {
      console.log(err);
      return;
    }
    console.log('response:', res.body);

    // Check signatory
    const { messages, signatures } = res.body;
    for (let i = 0; i < messages.length; i++) {
      console.log(`Message ${i} - expect true: ` + verify(messages[i], signatures[i], publicKeyBase58))
    }
    console.log("Invalid sig - expect false: " + verify(messageFalse, signatureFalse, publicKeyBase58))
  });

const verify = (messageHex, signatureBase58, pkBase58) => {
  if (!signatureBase58.startsWith("spsig")) {
    throw new Error("Signature must start with 'spsig'")
  }
  if (!pkBase58.startsWith("sppk")) {
    throw new Error("Public Key must start with 'sppk'")
  }
  const signatureBytes = base58Check.decode(signatureBase58).slice(5)
  const signatureHex = Buffer.from(signatureBytes).toString('hex')
  const publicKeyBytes = base58Check.decode(pkBase58).slice(4)
  const elliptic = new EC('secp256k1');
  var publicKey = elliptic.keyFromPublic(publicKeyBytes, 'hex');
  const messageHashBytes = blakejs.blake2b(new Buffer(messageHex, 'hex'), null, 32)
  const messageHashHex = Buffer.from(messageHashBytes).toString('hex')
  const r = signatureHex.slice(0, 64)
  const s = signatureHex.slice(64)
  const signatureObject = {
    r,
    s
  }
  return publicKey.verify(messageHashHex, signatureObject)
}
