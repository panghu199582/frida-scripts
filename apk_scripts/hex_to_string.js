
function hexToAscii(hexStr) {
    let str = '';
    for (let i = 0; i < hexStr.length; i += 2) {
        str += String.fromCharCode(parseInt(hexStr.substr(i, 2), 16));
    }
    return str;
}

const hex = "444556303030303734373135345451355755455537323535303835373237343130323138313839";
const plaintext = hexToAscii(hex);

console.log(`Hex: ${hex}`);
console.log(`Str: ${plaintext}`);
