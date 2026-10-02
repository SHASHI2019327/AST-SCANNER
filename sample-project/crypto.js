const crypto = require("crypto");

const hash = crypto.createHash("sha256");

const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
);

const keyPair = crypto.generateKeyPairSync(
    "rsa",
    {
        modulusLength: 2048
    }
);