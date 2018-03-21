
const querystring = require('querystring');
const crypto = require('crypto');

function Signature(setting) {
    this.version = setting.version || '1.0.0';
    this.key = setting.key;
    this.secret = setting.secret;
}

Signature.prototype.sig = function (uri, params) {
    var authParameter = {
        'auth_version': this.version,
        'auth_key': this.key,
        'auth_timestamp': getTime()
    };
    var fullParameters = Object.assign({}, authParameter, params);
    var hash = getSignatureHash(uri, fullParameters, this.secret)
    var authData = Object.assign({}, authParameter, {
        auth_signature: hash
    });

    return Object.assign({}, authData, params);
};

Signature.prototype.auth = function (uri, params) {
    var auth_signature = params.auth_signature;
    delete params.auth_signature;
    var hash = getSignatureHash(uri, params, this.secret)
    if(auth_signature != hash) {
        return false;
    }
    return true;
}

function getSignatureHash(uri, params, secret) {
    var data = decodeURIComponent(querystring.stringify(ksort(params))).toLowerCase();
    var payload = ['POST', uri, data];
    var text = payload.join('\n');
    var hash = crypto.createHmac('sha256', secret).update(text).digest('hex');
    return hash
}

function ksort(obj) {
    var keys = Object.keys(obj).sort(),
        sortedObj = {};

    for (var i in keys) {
        sortedObj[keys[i]] = obj[keys[i]];
    }

    return sortedObj;
}

function getTime() {
    return Math.round(new Date().getTime() / 1000);
}

module.exports = Signature;