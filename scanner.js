const fs = require("fs");
const path = require("path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;


// ============================================================
// CONFIGURATION
// ============================================================

const DEFAULT_TARGET = "./sample-project";

const SUPPORTED_EXTENSIONS = [
    ".js",
    ".mjs",
    ".cjs"
];

const IGNORED_DIRECTORIES = new Set([
    "node_modules",
    ".git",
    ".github",
    "dist",
    "build",
    "coverage"
]);


// ============================================================
// CREATE FINDING
// ============================================================

function createFinding({
    algorithm,
    family,
    type,
    keySize = null,
    mode = null,
    operation = null,
    api,
    file,
    line
}) {
    return {
        algorithm,
        family,
        type,
        keySize,
        mode,
        operation,
        api,
        library: "Node.js crypto",
        file,
        line
    };
}


// ============================================================
// CHECK WHETHER A MODULE IS NODE CRYPTO
// ============================================================

function isCryptoModule(value) {

    return (
        value === "crypto" ||
        value === "node:crypto"
    );
}


// ============================================================
// GET STRING VALUE FROM AST NODE
// ============================================================

function getStringValue(node) {

    if (!node) {
        return null;
    }

    if (node.type === "StringLiteral") {
        return node.value;
    }

    if (
        node.type === "Literal" &&
        typeof node.value === "string"
    ) {
        return node.value;
    }

    return null;
}


// ============================================================
// DETECT CRYPTO USAGE IN ONE FILE
// ============================================================

function scanFile(filePath, projectRoot) {

    const findings = [];

    let sourceCode;

    try {

        sourceCode =
            fs.readFileSync(
                filePath,
                "utf8"
            );

    }
    catch (error) {

        console.log(
            `Could not read: ${filePath}`
        );

        return findings;
    }


    let ast;

    try {

        ast =
            parser.parse(
                sourceCode,
                {
                    sourceType: "unambiguous",

                    plugins: [
                        "jsx",
                        "typescript"
                    ]
                }
            );

    }
    catch (error) {

        console.log(
            `Could not parse: ${path.relative(
                projectRoot,
                filePath
            )}`
        );

        console.log(
            `Reason: ${error.message}`
        );

        return findings;
    }


    // ========================================================
    // TRACK CRYPTO IDENTIFIERS
    // ========================================================

    const cryptoObjects = new Set();

    const importedCryptoFunctions = new Map();


    // Default/common name

    cryptoObjects.add("crypto");


    // ========================================================
    // FIRST PASS
    //
    // Find:
    //
    // const crypto = require("crypto")
    //
    // const myCrypto = require("crypto")
    //
    // const { createHash } = require("crypto")
    //
    // const { createHash: hash } = require("crypto")
    //
    // import crypto from "crypto"
    //
    // import { createHash } from "crypto"
    // ========================================================

    traverse(ast, {

        // ----------------------------------------------------
        // require("crypto")
        // ----------------------------------------------------

        VariableDeclarator(pathNode) {

            const node =
                pathNode.node;


            if (
                !node.init ||
                node.init.type !== "CallExpression"
            ) {
                return;
            }


            const callee =
                node.init.callee;


            if (
                callee.type !== "Identifier" ||
                callee.name !== "require"
            ) {
                return;
            }


            const moduleName =
                getStringValue(
                    node.init.arguments[0]
                );


            if (!isCryptoModule(moduleName)) {
                return;
            }


            // ------------------------------------------------
            // const crypto = require("crypto")
            // ------------------------------------------------

            if (
                node.id.type === "Identifier"
            ) {

                cryptoObjects.add(
                    node.id.name
                );

                return;
            }


            // ------------------------------------------------
            // const {
            //     createHash,
            //     createHmac
            // } = require("crypto")
            // ------------------------------------------------

            if (
                node.id.type === "ObjectPattern"
            ) {

                for (
                    const property
                    of node.id.properties
                ) {

                    if (
                        property.type !==
                        "ObjectProperty"
                    ) {
                        continue;
                    }


                    const importedName =
                        property.key.name ||
                        property.key.value;


                    let localName = null;


                    if (
                        property.value.type ===
                        "Identifier"
                    ) {

                        localName =
                            property.value.name;
                    }


                    if (
                        property.value.type ===
                        "AssignmentPattern" &&
                        property.value.left.type ===
                        "Identifier"
                    ) {

                        localName =
                            property.value.left.name;
                    }


                    if (
                        importedName &&
                        localName
                    ) {

                        importedCryptoFunctions.set(
                            localName,
                            importedName
                        );
                    }
                }
            }
        },


        // ----------------------------------------------------
        // import crypto from "crypto"
        //
        // import * as crypto from "crypto"
        //
        // import {
        //     createHash
        // } from "crypto"
        // ----------------------------------------------------

        ImportDeclaration(pathNode) {

            const node =
                pathNode.node;


            const moduleName =
                getStringValue(
                    node.source
                );


            if (!isCryptoModule(moduleName)) {
                return;
            }


            for (
                const specifier
                of node.specifiers
            ) {

                // --------------------------------------------
                // import crypto from "crypto"
                // --------------------------------------------

                if (
                    specifier.type ===
                    "ImportDefaultSpecifier"
                ) {

                    cryptoObjects.add(
                        specifier.local.name
                    );
                }


                // --------------------------------------------
                // import * as crypto from "crypto"
                // --------------------------------------------

                else if (
                    specifier.type ===
                    "ImportNamespaceSpecifier"
                ) {

                    cryptoObjects.add(
                        specifier.local.name
                    );
                }


                // --------------------------------------------
                // import {
                //     createHash
                // } from "crypto"
                // --------------------------------------------

                else if (
                    specifier.type ===
                    "ImportSpecifier"
                ) {

                    const importedName =
                        specifier.imported.name ||
                        specifier.imported.value;


                    const localName =
                        specifier.local.name;


                    importedCryptoFunctions.set(
                        localName,
                        importedName
                    );
                }
            }
        }
    });


    // ========================================================
    // SECOND PASS
    //
    // Detect actual crypto calls
    // ========================================================

    traverse(ast, {

        CallExpression(pathNode) {

            const node =
                pathNode.node;

            const callee =
                node.callee;


            const line =
                node.loc &&
                node.loc.start.line;


            const relativeFile =
                path.relative(
                    projectRoot,
                    filePath
                );


            // =================================================
            // CASE 1
            //
            // crypto.createHash(...)
            // myCrypto.createHash(...)
            // =================================================

            if (
                callee.type ===
                "MemberExpression" &&
                !callee.computed &&
                callee.object.type ===
                "Identifier" &&
                callee.property.type ===
                "Identifier"
            ) {

                const objectName =
                    callee.object.name;

                const methodName =
                    callee.property.name;


                if (
                    cryptoObjects.has(
                        objectName
                    )
                ) {

                    processCryptoMethod(
                        methodName,
                        node,
                        relativeFile,
                        line,
                        findings
                    );
                }


                return;
            }


            // =================================================
            // CASE 2
            //
            // createHash(...)
            // createHmac(...)
            // createCipheriv(...)
            //
            // where they came from:
            //
            // const { createHash } = require("crypto")
            // =================================================

            if (
                callee.type ===
                "Identifier"
            ) {

                const functionName =
                    callee.name;


                if (
                    importedCryptoFunctions.has(
                        functionName
                    )
                ) {

                    const actualCryptoMethod =
                        importedCryptoFunctions.get(
                            functionName
                        );


                    processCryptoMethod(
                        actualCryptoMethod,
                        node,
                        relativeFile,
                        line,
                        findings
                    );
                }
            }
        }
    });


    return findings;
}


// ============================================================
// PROCESS CRYPTO METHOD
// ============================================================

function processCryptoMethod(
    methodName,
    node,
    relativeFile,
    line,
    findings
) {


    // ========================================================
    // createHash
    // ========================================================

    if (
        methodName === "createHash"
    ) {

        const firstArgument =
            node.arguments[0];


        let algorithm =
            getStringValue(
                firstArgument
            ) ||
            "unknown";


        algorithm =
            normalizeAlgorithm(
                algorithm
            );


        const hashInfo =
            getHashInformation(
                algorithm
            );


        findings.push(
            createFinding({
                algorithm:
                    hashInfo.algorithm,

                family:
                    hashInfo.family,

                type:
                    "hash",

                keySize:
                    null,

                mode:
                    null,

                operation:
                    "hash",

                api:
                    "crypto.createHash",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // createCipheriv
    // ========================================================

    if (
        methodName ===
        "createCipheriv"
    ) {

        const firstArgument =
            node.arguments[0];


        let algorithm =
            getStringValue(
                firstArgument
            ) ||
            "unknown";


        const cipherInfo =
            getCipherInformation(
                algorithm
            );


        findings.push(
            createFinding({
                algorithm:
                    cipherInfo.algorithm,

                family:
                    cipherInfo.family,

                type:
                    "symmetric-encryption",

                keySize:
                    cipherInfo.keySize,

                mode:
                    cipherInfo.mode,

                operation:
                    "encrypt",

                api:
                    "crypto.createCipheriv",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // createDecipheriv
    // ========================================================

    if (
        methodName ===
        "createDecipheriv"
    ) {

        const firstArgument =
            node.arguments[0];


        let algorithm =
            getStringValue(
                firstArgument
            ) ||
            "unknown";


        const cipherInfo =
            getCipherInformation(
                algorithm
            );


        findings.push(
            createFinding({
                algorithm:
                    cipherInfo.algorithm,

                family:
                    cipherInfo.family,

                type:
                    "symmetric-encryption",

                keySize:
                    cipherInfo.keySize,

                mode:
                    cipherInfo.mode,

                operation:
                    "decrypt",

                api:
                    "crypto.createDecipheriv",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // generateKeyPairSync
    // ========================================================

    if (
        methodName ===
        "generateKeyPairSync"
    ) {

        const firstArgument =
            node.arguments[0];


        const algorithm =
            getStringValue(
                firstArgument
            ) ||
            "unknown";


        const keyInfo =
            getPublicKeyInformation(
                algorithm,
                node.arguments[1]
            );


        findings.push(
            createFinding({
                algorithm:
                    keyInfo.algorithm,

                family:
                    keyInfo.family,

                type:
                    "public-key",

                keySize:
                    keyInfo.keySize,

                mode:
                    null,

                operation:
                    "key-generation",

                api:
                    "crypto.generateKeyPairSync",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // createHmac
    // ========================================================

    if (
        methodName ===
        "createHmac"
    ) {

        const firstArgument =
            node.arguments[0];


        const algorithm =
            normalizeAlgorithm(
                getStringValue(
                    firstArgument
                ) ||
                "unknown"
            );


        const hmacAlgorithm =
            algorithm === "unknown"
                ? "HMAC-UNKNOWN"
                : `HMAC-${algorithm}`;


        findings.push(
            createFinding({
                algorithm:
                    hmacAlgorithm,

                family:
                    "HMAC",

                type:
                    "message-authentication",

                keySize:
                    null,

                mode:
                    null,

                operation:
                    "authentication",

                api:
                    "crypto.createHmac",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // createSign
    // ========================================================

    if (
        methodName ===
        "createSign"
    ) {

        findings.push(
            createFinding({
                algorithm:
                    getStringValue(
                        node.arguments[0]
                    ) ||
                    "unknown",

                family:
                    "signature",

                type:
                    "digital-signature",

                keySize:
                    null,

                mode:
                    null,

                operation:
                    "sign",

                api:
                    "crypto.createSign",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }


    // ========================================================
    // createVerify
    // ========================================================

    if (
        methodName ===
        "createVerify"
    ) {

        findings.push(
            createFinding({
                algorithm:
                    getStringValue(
                        node.arguments[0]
                    ) ||
                    "unknown",

                family:
                    "signature",

                type:
                    "digital-signature",

                keySize:
                    null,

                mode:
                    null,

                operation:
                    "verify",

                api:
                    "crypto.createVerify",

                file:
                    relativeFile,

                line
            })
        );


        return;
    }
}


// ============================================================
// ALGORITHM NORMALIZATION
// ============================================================

function normalizeAlgorithm(
    algorithm
) {

    if (!algorithm) {
        return "unknown";
    }


    const normalized =
        algorithm
            .toLowerCase()
            .replace(/[_\s]/g, "-");


    const aliases = {

        "sha256": "SHA-256",
        "sha-256": "SHA-256",

        "sha384": "SHA-384",
        "sha-384": "SHA-384",

        "sha512": "SHA-512",
        "sha-512": "SHA-512",

        "sha1": "SHA-1",
        "sha-1": "SHA-1",

        "md5": "MD5"
    };


    return (
        aliases[normalized] ||
        algorithm
    );
}


// ============================================================
// HASH INFORMATION
// ============================================================

function getHashInformation(
    algorithm
) {

    const upper =
        algorithm.toUpperCase();


    if (
        upper === "SHA-256" ||
        upper === "SHA256"
    ) {

        return {
            algorithm: "SHA-256",
            family: "SHA-2"
        };
    }


    if (
        upper === "SHA-384" ||
        upper === "SHA384"
    ) {

        return {
            algorithm: "SHA-384",
            family: "SHA-2"
        };
    }


    if (
        upper === "SHA-512" ||
        upper === "SHA512"
    ) {

        return {
            algorithm: "SHA-512",
            family: "SHA-2"
        };
    }


    if (
        upper === "SHA-1" ||
        upper === "SHA1"
    ) {

        return {
            algorithm: "SHA-1",
            family: "SHA-1"
        };
    }


    if (
        upper === "MD5"
    ) {

        return {
            algorithm: "MD5",
            family: "MD"
        };
    }


    return {
        algorithm,
        family: "unknown"
    };
}


// ============================================================
// CIPHER INFORMATION
// ============================================================

function getCipherInformation(
    algorithm
) {

    if (!algorithm) {

        return {
            algorithm: "unknown",
            family: "unknown",
            keySize: null,
            mode: null
        };
    }


    const upper =
        algorithm.toUpperCase();


    // AES-128/192/256 + modes

    let match =
        upper.match(
            /^AES-(128|192|256)-(GCM|CBC|CTR|CCM|ECB|CFB|OFB)$/
        );


    if (match) {

        return {
            algorithm:
                `AES-${match[1]}-${match[2]}`,

            family:
                "AES",

            keySize:
                Number(match[1]),

            mode:
                match[2]
        };
    }


    // AES-128/192/256

    match =
        upper.match(
            /^AES-(128|192|256)$/
        );


    if (match) {

        return {
            algorithm:
                `AES-${match[1]}`,

            family:
                "AES",

            keySize:
                Number(match[1]),

            mode:
                null
        };
    }


    // ChaCha20-Poly1305

    if (
        upper ===
        "CHACHA20-POLY1305"
    ) {

        return {
            algorithm:
                "ChaCha20-Poly1305",

            family:
                "ChaCha20",

            keySize:
                256,

            mode:
                "Poly1305"
        };
    }


    return {
        algorithm,
        family: "unknown",
        keySize: null,
        mode: null
    };
}


// ============================================================
// PUBLIC KEY INFORMATION
// ============================================================

function getPublicKeyInformation(
    algorithm,
    optionsNode
) {

    const normalized =
        algorithm.toLowerCase();


    // --------------------------------------------------------
    // RSA
    // --------------------------------------------------------

    if (
        normalized === "rsa"
    ) {

        let keySize = null;


        if (
            optionsNode &&
            optionsNode.type ===
            "ObjectExpression"
        ) {

            for (
                const property
                of optionsNode.properties
            ) {

                if (
                    property.type ===
                    "ObjectProperty" &&
                    property.key.type ===
                    "Identifier" &&
                    property.key.name ===
                    "modulusLength"
                ) {

                    if (
                        property.value.type ===
                        "NumericLiteral"
                    ) {

                        keySize =
                            property.value.value;
                    }
                }
            }
        }


        return {
            algorithm:
                "RSA",

            family:
                "RSA",

            keySize
        };
    }


    // --------------------------------------------------------
    // EC / ECDSA
    // --------------------------------------------------------

    if (
        normalized === "ec" ||
        normalized === "ecdsa"
    ) {

        return {
            algorithm:
                "ECDSA",

            family:
                "ECDSA",

            keySize:
                null
        };
    }


    // --------------------------------------------------------
    // Ed25519
    // --------------------------------------------------------

    if (
        normalized === "ed25519"
    ) {

        return {
            algorithm:
                "Ed25519",

            family:
                "EdDSA",

            keySize:
                null
        };
    }


    return {
        algorithm,
        family: "unknown",
        keySize: null
    };
}


// ============================================================
// RECURSIVE FILE DISCOVERY
// ============================================================

function getJavaScriptFiles(
    directory
) {

    const files = [];


    function walk(
        currentDirectory
    ) {

        let entries;


        try {

            entries =
                fs.readdirSync(
                    currentDirectory,
                    {
                        withFileTypes:
                            true
                    }
                );

        }
        catch (error) {

            console.log(
                `Could not access: ${currentDirectory}`
            );

            return;
        }


        for (
            const entry
            of entries
        ) {

            const fullPath =
                path.join(
                    currentDirectory,
                    entry.name
                );


            // ------------------------------------------------
            // Directory
            // ------------------------------------------------

            if (
                entry.isDirectory()
            ) {

                if (
                    IGNORED_DIRECTORIES.has(
                        entry.name
                    )
                ) {

                    continue;
                }


                walk(
                    fullPath
                );
            }


            // ------------------------------------------------
            // File
            // ------------------------------------------------

            else if (
                entry.isFile()
            ) {

                const extension =
                    path.extname(
                        entry.name
                    ).toLowerCase();


                if (
                    SUPPORTED_EXTENSIONS.includes(
                        extension
                    )
                ) {

                    files.push(
                        fullPath
                    );
                }
            }
        }
    }


    walk(
        directory
    );


    return files;
}


// ============================================================
// TARGET RESOLUTION
// ============================================================

const targetArgument =
    process.argv[2] ||
    DEFAULT_TARGET;


const targetPath =
    path.resolve(
        targetArgument
    );


if (
    !fs.existsSync(
        targetPath
    )
) {

    console.error(
        `\nTarget does not exist: ${targetPath}\n`
    );

    process.exit(1);
}


// ============================================================
// DETERMINE PROJECT ROOT
// ============================================================

const stats =
    fs.statSync(
        targetPath
    );


let projectRoot;


if (
    stats.isDirectory()
) {

    projectRoot =
        targetPath;

}
else {

    projectRoot =
        path.dirname(
            targetPath
        );
}


// ============================================================
// FIND FILES
// ============================================================

let filesToScan;


if (
    stats.isDirectory()
) {

    filesToScan =
        getJavaScriptFiles(
            targetPath
        );

}
else {

    filesToScan =
        [targetPath];
}


// ============================================================
// DISPLAY HEADER
// ============================================================

console.log("");

console.log(
    "========================================"
);

console.log(
    "          AST CRYPTO SCANNER"
);

console.log(
    "========================================"
);

console.log("");

console.log(
    "Target:",
    targetPath
);

console.log("");

console.log(
    "JavaScript files found:",
    filesToScan.length
);

console.log("");


// ============================================================
// SCAN ALL FILES
// ============================================================

let allFindings = [];


for (
    const file
    of filesToScan
) {

    const relativeFile =
        path.relative(
            projectRoot,
            file
        );


    console.log(
        `Scanning: ${relativeFile}`
    );


    const findings =
        scanFile(
            file,
            projectRoot
        );


    allFindings =
        allFindings.concat(
            findings
        );
}


// ============================================================
// SAVE FINDINGS
// ============================================================

const findingsPath =
    path.join(
        __dirname,
        "findings.json"
    );


fs.writeFileSync(
    findingsPath,
    JSON.stringify(
        allFindings,
        null,
        2
    ),
    "utf8"
);


// ============================================================
// DISPLAY RESULTS
// ============================================================

console.log("");

console.log(
    "----------------------------------------"
);

console.log(
    "Crypto Findings"
);

console.log(
    "----------------------------------------"
);

console.log(
    JSON.stringify(
        allFindings,
        null,
        2
    )
);

console.log("");

console.log(
    "----------------------------------------"
);

console.log(
    "Files scanned:",
    filesToScan.length
);

console.log(
    "Crypto assets found:",
    allFindings.length
);

console.log(
    "----------------------------------------"
);

console.log("");

console.log(
    "Finding file updated: findings.json"
);

console.log("");