const crypto = require('crypto');

// 1. Captured Key (HMAC-SHA256)
const keyHex = "7c57a62f0945e1175ae978aca7278a8b99428c6a0e4207e5d98fee8202a03d05";
const key = Buffer.from(keyHex, 'hex');

// 2. Target Hash (from Step 767 log)
// hashReqBody: 7WQv9hOpbJx5+7OQnsEZjsB1XtxWcy3rWkfhL8UVdEw=
const targetHash = "7WQv9hOpbJx5+7OQnsEZjsB1XtxWcy3rWkfhL8UVdEw=";

// 3. Encrypted ReqBody (Base64) from Step 767
const reqBody = "09mL91exHniLNzbfv7fSF6rBG1kCNvBKIpUNqoDqhZIgCOaxCbOQr3aJKpSruZd1PB15Vs2gzzFkCnasUW/vcOF61buaOrGIo64aJc8F+HEXUt2ssS6Q8xqqvOn3nlnZV7Rd9u77rKvThNqORPsNs6yZK+QYN9DWaMn8FoYM5F+PDKxNLQKBE5sqg7hoXoYDYyx1gpwVMluAZ4VHlEeEFrNAdb+4fT189x1zk7ZjRsinc1bB6ihOb6+aisM2cqo4Rq0/HuUzHPgFieXZu8/D1Uwva2vuutySrHkkiPpn3CtIJfXKs0rIWM9GfLQYfg0wQA82v80lymoar4FQ33ht0mv7m39exC5zZ1E6eLyONBtElayZKz4Nbr1csIoX7WjJ4hdBFfGvf7EudNm9OH4uf+zdPw0tWObTaMZEIpgxfYJQ6t7Dfh86mzMPNe24tWzeRqHdQ8eSWJ6BdSZh1hRAmhHgrUjPRxdRwL6fEgW4IePpuTTyJOq39vNQiUiRw+HBorQPf9V+84twmtyBwI9/BA9pTjMslfSreO+8q6Vwn+BYkbSvw/pvx0ViS4DW5SnV1G/kTJ/1qR6YQmk62UlzF2Uv2/fuLtpdxkleTktaVK7SWtA9N/zykRC9UdzmsRNZPWhx+xur0zvJ6ant5YPpKyyCjcnqLiipP2hiWjZvU0aK7blfoeCfE7pKu/XG56iEPSe9cpEQKrgA5slG5MzP/mIRn0J+YfRQQtLI6Ny1ljUCheBMFb9lw5siVuSd6sKSQQyER8s+OSMjGyGNCP6nnpEA1vyDpJ/6dMko7WxZZyAbuwLphmF7i34INRlE9RnfLMYbJxgP4x+CGNbNVAy3zHx42nQ1DFYv8fB9hvT/ijhPf/By4/wKyjg0QPFuyHUdx00O0OECDlIjnfrSKjJOybzTXSHLM30NmluSfBkAH33kvVURkYRYL1zu2lE30RYmOU7YBdpMxx+EJ28/5xytln2wsNsDYLziNs4ka+Hyhc0BNJdwtI+uDBnbkItduNJ5eBZS+Savv2N/5vj6IevhzZyNnZjV2IJSDSokHHMQNcD+MDCFpVSZhAsofCZkqhTyD8WWV5W28mnIm9HGIBCN/h+5d2mKO3ADP8mBj6LipwrudbA8nVDBsb/sm7MWrmzNo/TrIc7fpGVGSgtCdPlu8gyx71cnMwTiwxs5greXC6D2JxEP9f7pHBZY77iDP/WGIL+tEQMgaDr0ZpJjOuHAMwc2+yQO/ILZrH//oknkE8cY4kl6BUFEVAbwy4Oe4n44kLh9jHIRTBDggi+Rww7/26ZOG/a8WtucisFUSXfBtuSygdwBtP4huod8eoqGMq5GJICbqM3KyHNN7VCGSkMIrzFxNjz0/HWq9cafM8xFxEXRJnr4Yjohai0vuyJITkB5cFxBzbhmy5mPSRfDmbEUA795HLosSMzChDjZvXdHOIYuu0eidVheZD5Kzy8JnIOBE4tQgEStLVF1Ao9pxMHZ/YjbDMZ9415iQpjnUD0rqkyh65t8LBCS78RcXLrmS6eIXCBNXy+HJQdZt+Ehb8nq9MngfpNXU5z4jKNSTlo1SZTRfrvPDOhcuzEH25mSv0ENGFhnYq2q4RWRAKz84Je6OH5CFKSJK6/3N9h/T6M+ZCLHXgOQTwzNhXXFziFAQgSiYWaGtwtwtQMjVSwq2BCAnq2r8AV4OhL7Eg8U+5jfVhc/7ctchfYkUj9XUNtK8a/I+nEI5jvhUxB7g+Wx6Fvg260XNs7JXSCYELIgeRikiXAld7+EyeC+syHL+yIGKMCpukNP1ukAjb558imWnUo4PuLeUw2kglglq6DBsKcVngCpU+lw4M1MhOQlZuIH9j3lT864GxkPy2IEniDhgvd/6M9WJd++pimokZln8gujwj8N/k53l54SnDNROO15zSiwV5z70vpj30E5EFs0Z2wZx4DvjHX9lEHghdLBmieugHM=";

// 4. Request Header (JSON String)
// Note: In the final JSON, this corresponds to the value of "requestHeader" key.
const requestHeader = `{"osType":"AND","TranSeq":"{TranSeq}","trandate":"24/12/2025 18:58:12","encrypt":false,"ErrorCode":0,"appName":"PGBankMobile","gcmId":"d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg","devSeq":"1","version":"3.2.9","language":"vi-vn","isRoot":"false","IpAddress":"103.63.114.42","UniqueDeviceId":"a2a04ece-db28-353c-900f-5bc7cb8f56ed","isNfcAvailable":"Y"}`;

function tryHmac(input, label) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(input);
    const result = hmac.digest('base64');
    // console.log(`[${label}] \n   Result: ${result}`);
    if (result === targetHash) {
        console.log(`\n🎉 MATCH FOUND! Format: ${label}`);
        console.log(`   Hash: ${result}`);
        return true;
    }
    return false;
}

console.log("--- Pgbank Hash Bruteforce ---");
console.log("Target: " + targetHash);

// Attempt 1: Header + Body (Concatenated Strings)
tryHmac(requestHeader + reqBody, "requestHeader + reqBody");

// Attempt 2: Body + Header
tryHmac(reqBody + requestHeader, "reqBody + requestHeader");

// Attempt 3: Just Header
tryHmac(requestHeader, "requestHeader");

// Attempt 4: Just Body (Again, just in case)
tryHmac(reqBody, "reqBodyOnly");

// Attempt 5: Maybe with a separator?
tryHmac(requestHeader + "." + reqBody, "Header.Body");

console.log("--- End ---");
