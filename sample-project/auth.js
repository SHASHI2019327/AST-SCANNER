const crypto = require("crypto");

const hmac = crypto.createHmac(
    "sha256",
    secret
);