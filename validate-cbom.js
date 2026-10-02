const fs = require("fs");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");


// ============================================================
// 1. Load CycloneDX 1.6 schema
// ============================================================

const cyclonedxSchema = JSON.parse(

    fs.readFileSync(

        "./schema/bom-1.6.schema.json",

        "utf8"

    )

);


// ============================================================
// 2. Load SPDX schema
// ============================================================

const spdxSchema = JSON.parse(

    fs.readFileSync(

        "./schema/spdx.schema.json",

        "utf8"

    )

);


// ============================================================
// 3. Load JSF schema
// ============================================================

const jsfSchema = JSON.parse(

    fs.readFileSync(

        "./schema/jsf-0.82.schema.json",

        "utf8"

    )

);


// ============================================================
// 4. Load CBOM
// ============================================================

const cbom = JSON.parse(

    fs.readFileSync(

        "./cbom.json",

        "utf8"

    )

);


// ============================================================
// 5. Create AJV
// ============================================================

const ajv = new Ajv({

    allErrors: true,

    strict: false

});


// ============================================================
// 6. Add format support
// ============================================================

addFormats(ajv);


// ============================================================
// 7. Register SPDX schema
// ============================================================

ajv.addSchema(

    spdxSchema,

    "http://cyclonedx.org/schema/spdx.schema.json"

);


// ============================================================
// 8. Register JSF schema
// ============================================================

ajv.addSchema(

    jsfSchema,

    "http://cyclonedx.org/schema/jsf-0.82.schema.json"

);


// ============================================================
// 9. Compile CycloneDX schema
// ============================================================

let validate;


try {

    validate =
        ajv.compile(
            cyclonedxSchema
        );

}

catch (error) {

    console.error(
        "\nSchema compilation failed:"
    );

    console.error(
        error.message
    );

    process.exit(1);

}


// ============================================================
// 10. Validate CBOM
// ============================================================

const valid =
    validate(cbom);


// ============================================================
// 11. Result
// ============================================================

if (valid) {

    console.log(
        "\n================================="
    );

    console.log(
        "CBOM VALIDATION SUCCESSFUL"
    );

    console.log(
        "================================="
    );


    console.log(
        "\nCycloneDX version:",
        cbom.specVersion
    );


    console.log(
        "Cryptographic assets:",
        cbom.components
            ? cbom.components.length
            : 0
    );


    console.log(
        "\ncbom.json is valid according to"
    );

    console.log(
        "the CycloneDX 1.6 JSON Schema."
    );

}

else {

    console.log(
        "\n================================="
    );

    console.log(
        "CBOM VALIDATION FAILED"
    );

    console.log(
        "=================================\n"
    );


    console.log(
        "Validation errors:"
    );


    console.log(

        JSON.stringify(

            validate.errors,

            null,

            2

        )

    );

}