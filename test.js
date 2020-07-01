const base58Check = require('bs58check')
const EC = require('elliptic').ec;
const blakejs = require('blakejs')
const publicKeyBase58 = "sppk7aCfP6jEZ2ktX2Y3v9bXB4ohKsP9LYaiyz2B1r81s2giY8Cyepu"
const messageHex_1 = "05070701000000074254432d555344070700808a97ef0b070700a0b39eef0b070700a0daefec47070700b097e0ee4707070090beeeec4707070090b79aed4700938ec106"
const signatureBase58_1 = "spsig1cLwzXQEprTYcS9uLSRA8hqC1ZmJkayrbuDyaM31zHes8Jt2QRceJQcTFdjfAqQxYg82qg1GHavgzKHLZ4bxsyQokRxNNu"
const messageHex_2 = "05070701000000074554482d555344070700808a97ef0b070700a0b39eef0b070700a09db5ec01070700b0b9b6ec0107070090ea91ec01070700b0a294ec01009284eedd01"
const signatureBase58_2 = "spsig1aud3o3iTfB9tP2HQgE4RZYqmyb56PgjGh1e2ZnK2LjixjsqAsTDcN8UnSt92uxm9nqz9uVikRSnPHQ3hFd4Q81tz3uHwi"
const verify = (messageHex, signatureBase58, publicKeyBase58) => {
    if (!signatureBase58.startsWith("spsig")) {
        throw new Error("Signature must start with 'spsig'")
    }
    if (!publicKeyBase58.startsWith("sppk")) {
        throw new Error("Public Key must start with 'sppk'")
    }
    const signatureBytes = base58Check.decode(signatureBase58).slice(5)
    const signatureHex = Buffer.from(signatureBytes).toString('hex')
    const publicKeyBytes = base58Check.decode(publicKeyBase58).slice(4)
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
// Expect true, message and signature are valid.
console.log("Expect true: " + verify(messageHex_1, signatureBase58_1, publicKeyBase58))
// Expect false, message and signature are mismatched.
console.log("Expect false: " + verify(messageHex_2, signatureBase58_1, publicKeyBase58))