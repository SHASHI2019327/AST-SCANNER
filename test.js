const crypto = require("crypto");

const hash = crypto.createHash("sha256");

const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
);

const { publicKey, privateKey } =
    crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048
    });

const hmac = crypto.createHmac(
    "sha256",
    secretKey
);