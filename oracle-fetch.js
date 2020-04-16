require('dotenv').config();
const superagent = require('superagent');
const crypto = require('crypto');

const key_id = process.env.API_KEY_ID;
const secret = process.env.API_SECRET;
const passphrase = process.env.API_PASSPHRASE;

const apiURI = 'https://api.pro.coinbase.com';

var timestamp = Date.now() / 1000;
var requestPath = '/oracle';

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
    console.log(res.body);
  });