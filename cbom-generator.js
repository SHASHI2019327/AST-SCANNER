const fs = require("fs");
const crypto = require("crypto");

// ============================================================
// 1. Load findings
// ============================================================

const findingsPath = "./findings.json";

if (!fs.existsSync(findingsPath)) {
    console.error("ERROR: findings.json not found.");
    console.error("Run: node scanner.js");
    process.exit(1);
}

const findings = JSON.parse(
    fs.readFileSync(findingsPath, "utf8")
);


// ============================================================
// 2. Generate BOM reference
// ============================================================

function createBomRef(finding) {
    return (
        "crypto/algorithm/" +
        finding.algorithm
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "")
    );
}


// ============================================================
// 3. Convert scanner finding to CycloneDX primitive
// ============================================================

function getPrimitive(finding) {

    const type = finding.type || "";
    const api = finding.api || "";
    const algorithm = (
        finding.algorithm || ""
    ).toUpperCase();


    // Hash
    if (type === "hash") {
        return "hash";
    }


    // HMAC / MAC
    if (
        type === "message-authentication" ||
        algorithm.startsWith("HMAC") ||
        api.includes("createHmac")
    ) {
        return "mac";
    }


    // AES-GCM and authenticated encryption
    if (
        type === "symmetric-encryption"
    ) {
        return "ae";
    }


    // RSA / ECDSA / public-key
    if (
        type === "public-key"
    ) {

        if (
            algorithm.includes("ECDSA") ||
            algorithm.includes("RSA")
        ) {
            return "pke";
        }

        return "pke";
    }


    return "unknown";
}


// ============================================================
// 4. Convert operation to CycloneDX cryptoFunction
// ============================================================

function getCryptoFunction(finding) {

    const operation =
        (finding.operation || "").toLowerCase();


    if (
        operation === "hash" ||
        operation === "hashing"
    ) {
        return "digest";
    }


    if (
        operation === "encrypt" ||
        operation === "encryption"
    ) {
        return "encrypt";
    }


    if (
        operation === "decrypt" ||
        operation === "decryption"
    ) {
        return "decrypt";
    }


    if (
        operation === "authentication"
    ) {
        return "tag";
    }


    if (
        operation === "key-generation"
    ) {
        return "keygen";
    }


    return "unknown";
}


// ============================================================
// 5. Extract parameter set
// ============================================================

function getParameterSet(finding) {

    if (
        finding.keySize !== null &&
        finding.keySize !== undefined
    ) {
        return String(finding.keySize);
    }

    return undefined;
}


// ============================================================
// 6. Create algorithm properties
// ============================================================

function createAlgorithmProperties(finding) {

    const properties = {};


    const primitive =
        getPrimitive(finding);

    properties.primitive = primitive;


    const parameterSet =
        getParameterSet(finding);

    if (parameterSet !== undefined) {
        properties.parameterSetIdentifier =
            parameterSet;
    }


    if (
        finding.mode !== null &&
        finding.mode !== undefined
    ) {
        properties.mode =
            String(finding.mode).toLowerCase();
    }


    // These fields are useful for AES-GCM
    if (primitive === "ae") {

        properties.executionEnvironment =
            "software-plain-ram";

        properties.implementationPlatform =
            "unknown";

        properties.certificationLevel = [
            "none"
        ];
    }


    properties.cryptoFunctions = [
        getCryptoFunction(finding)
    ];


    return properties;
}


// ============================================================
// 7. Create CycloneDX cryptographic asset
// ============================================================

function createCryptoComponent(finding) {

    const component = {

        type: "cryptographic-asset",

        name: finding.algorithm,

        "bom-ref": createBomRef(finding),

        cryptoProperties: {

            assetType: "algorithm",

            algorithmProperties:
                createAlgorithmProperties(
                    finding
                )
        },

        evidence: {

            occurrences: [

                {
                    location:
                        `${finding.file}:${finding.line}`
                }

            ]
        }
    };


    return component;
}


// ============================================================
// 8. Group identical cryptographic assets
// ============================================================

const assetMap = new Map();


for (const finding of findings) {

    const key =
        createBomRef(finding);


    if (!assetMap.has(key)) {

        assetMap.set(
            key,
            {
                finding,
                occurrences: []
            }
        );
    }


    const asset =
        assetMap.get(key);


    const occurrence =
        `${finding.file}:${finding.line}`;


    if (
        !asset.occurrences.includes(
            occurrence
        )
    ) {

        asset.occurrences.push(
            occurrence
        );
    }
}


// ============================================================
// 9. Build CycloneDX components
// ============================================================

const components = [];


for (const asset of assetMap.values()) {

    const component =
        createCryptoComponent(
            asset.finding
        );


    component.evidence.occurrences =
        asset.occurrences.map(
            location => ({
                location
            })
        );


    components.push(component);
}


// ============================================================
// 10. Generate CycloneDX 1.6 CBOM
// ============================================================

const cbom = {

    bomFormat: "CycloneDX",

    specVersion: "1.6",

    serialNumber:
        `urn:uuid:${crypto.randomUUID()}`,

    version: 1,

    components

};


// ============================================================
// 11. Write cbom.json
// ============================================================

fs.writeFileSync(

    "./cbom.json",

    JSON.stringify(
        cbom,
        null,
        2
    ),

    "utf8"
);


// ============================================================
// 12. Display result
// ============================================================

console.log("");
console.log("========================================");
console.log("   CYCLONEDX 1.6 CBOM GENERATED");
console.log("========================================");
console.log("");

console.log(
    "Findings processed:",
    findings.length
);

console.log(
    "Unique cryptographic assets:",
    components.length
);

console.log("");

console.log(
    "Output: cbom.json"
);

console.log("");

console.log(
    "CBOM generation completed successfully."
);

console.log("");