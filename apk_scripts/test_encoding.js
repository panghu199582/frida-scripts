const header = {
    date: "24/12/2025"
};

function stringifyHeader(headerObj) {
    let json = JSON.stringify(headerObj);
    // Mimic the escaping seen in logs: forward slash becomes \/
    // Since we are in JS string literal, '\\/' means literal backslash then forward slash
    return json.replace(/\//g, '\\/');
}

function gsonStringify(obj) {
    let json = JSON.stringify(obj);
    // Gson default escaping:
    // < -> \u003c
    // > -> \u003e
    // & -> \u0026 (sometimes)
    // = -> \u003d
    // ' -> \u0027
    return json.replace(/</g, '\\u003c')
               .replace(/>/g, '\\u003e')
               .replace(/=/g, '\\u003d')
               .replace(/&/g, '\\u0026')
               .replace(/'/g, '\\u0027');
}

const res = stringifyHeader(header);
console.log("--- Header Slash Test ---");
console.log("Raw object date:", header.date);
console.log("Result string:    ", res);
console.log("JSON.stringify output of Result:", JSON.stringify(res));

const body = {
    key: "abcdef==",
    xml: "<test>"
};
console.log("\n--- Gson Body Test ---");
console.log("Standard: ", JSON.stringify(body));
console.log("Gson Style:", gsonStringify(body));
