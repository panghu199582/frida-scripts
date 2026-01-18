const crypto = require('crypto');

// 之前提取的 HMAC Key
const HMAC_KEY_HEX = "7c572e3436526154564551624446416a506a6550725a766e336d764539662367";

function createHashReqBody(reqBodyBase64, requestHeaderStr) {
    if (!reqBodyBase64 || !requestHeaderStr) {
        console.error("需要 reqBody 和 requestHeader 才能生成 Hash");
        return null;
    }

    // 拼装规则：Header字符串 + Body密文
    const input = requestHeaderStr + reqBodyBase64;
    
    // 创建 HMAC-SHA256
    const hmac = crypto.createHmac('sha256', Buffer.from(HMAC_KEY_HEX, 'hex'));
    hmac.update(input);
    
    return hmac.digest('base64');
}

// 示例用法
const reqBody = "lAEmmEmA+RWxx97pmc3bjBeCDSbPYC0VEsZkjHzGTUjpuOG9GccqJ+mIeGHuxGMjSMOLiqWuvzZwSwCsvl77O0GCVQpUM1rvWE4ZyPBq2H2upm3WR0WpIZT9BLbziK0c3kPZdgB4iTCvFwRJIv3F/yyJhOVPDoWpKqdwdrcvWsh0d+SHaXsfp82sHH8l6fk2BpkcSK/J1GHJOh0DmFkNDbL8HBIMLaIn2cNB4extwKxR4tj3MOdJEDwxDpRj3tuwEp5/43AdQO78Qmd1rdfkTdBX+6APZx2YQZvkw2+RXpFhFGyOBAYY78UgjZdYfHiWlKDEBsLXthmFLPfKQ+8exTEP/b9BYnyGb0QPvylj4THr472Tg/H5RGF+KV4b8YDfycMmvbYA7EyDxYIPXJSc5ZnsMj6WjPXji23pj1rkfyWSli53nKDs/znCgwy7M3naBWIXNv7UURElx/+zo1FVMOUQ8Chqa4MNIwNri8xkE0ZH3lk2qAaT2XPwrj4GV8HNPleNkGODb9YsY7piNpiTT2+5KB0O3mnmerJ0E057g6BYsaPvHBJ6nwa+6bth6epxlZjGZ+s5jl8Up6D9l2/neS8iJFoCsbVSI1gd4FQ41E0YCPm+cglgRJiEb0C492WS+cfBC0t+4LODxcO9LRhJyfrMe50i9517of7+NI0QioIUK9p10oGAK+LVtEdBAnOIbf8PsaSJuMy7s8OTSsFs/EY95ApQVwSXp5VrZESSFCfqkMOmQSSIJVenGQSjpKyd3Y4+LqwVyZIG7/l/U5Fw97mVSpXzYKpE+EFe5yMkNn2l9McqSU8q3+I4HvlsCyxVa8xIc50ubAiKlTNBn4ZcYAvx/6NlLV1qwGa2vchDKgFI4zFzTj9t9wHn7q1Fc8uHqsx9M33ENfoT9zBFy/q0CNTWyIAkZd3Dnqu49ocCS+D+s1KPhEbpSiUg4hC/uaOGw1atuyZ2IZKT0mDcJLor43pa+7dPDQCINGS2x5ZERKSiLEIOBLWk6DUSADcmUXOk5pt8uKnr0w4uwCX7qZlHgjNpROuHcFIcaPoq5UDwz6IQOzBZChyt3b7ktwGrk2y8fGnQVUITXTDctlmSaxQps4NpAppuLrec03gOLsMnjALaeQlyXiy4NpIIyxAom/9bGuUaETqP71RTXDswMWbmsOLa/k+PIdkNzcQ+Z/gpMh6IaE2XRTyeAJR4YcwWvTSoN6Z5QIsp9t7/CLRmWUgdTMsUM49dNfDYxKv+0PX/YjxNbTQjiPHGUcvmyJxM76RYgCnM+gereLpaJGyXUoKSDRqbzkDhUWkwJmdQbYjxXJVC/msq1FH7hKYIt9i4QMlRwq3ogDvg1FP9bOveTopA2RRu3JwCTxT/go1hyWNXeH0kZM6P6AY4CIgK3t11bl+82Wt52LxQ20AY6TuMzzzVQNrqAi+PbqpVSjJjyuFgmL8Gpiz08xbHbrZaGfG+spcA0LpMsPPKK+g7a0Y+HjRv+qsSfPc6SX03K4GFLIeBue7qa+Nx1JbtuOmHwr8sUpwmlsulnyC+7951gE4uZf36YdR43Fm159YN+NkVIpnHeHhTz03UJ8HUMPgmRrcp2FBT8hlE+r3rbuC/ofDkTDHX2XOYKawOeXCSxGpDmzDSoMEkkKUYPPeifZXRKtYLq5YI95d9NgtRlTxmJVm2WrL7OrcHOjHIm3EN4VkGJJVQposts65bnbbpOGgVNW6++DwWt2cSmfbzR048EfOf8axU76OWBw4MDWT4ir8FFiv/LO3VGQw3gllGL91oMJjHyylcTxSHrIAmgadiNvjpKb4738hIn8VRz3pkLeAsgiqgJtSVWRdG8x1lpZi3TpampLOmWmTkh6k471m7uMYScd18D1+33tv8NdVqtWZNJp8FYA6JJ+RjDrIpvCtXLTi4/S7BKKGSjgeDwrWGS3DZOuuPb+UEbSqCsSHT4sO5JJPZSxA=";
const header = "{\"osType\":\"AND\",\"TranSeq\":\"{TranSeq}\",\"trandate\":\"24/12/2025 18:20:59\",\"encrypt\":false,\"ErrorCode\":0,\"appName\":\"PGBankMobile\",\"gcmId\":\"d98ACboBQDa8AF2GH7GT_r:APA91bEHfkDy3G-mBGSXAzUIQOYaaa47alXO2Y-jlv8sc2nHOya0UpCdVY6bkDMIYj8FPY09zOJU1Cz8e_vF5iJgNvSPeUID9i-PN0vZtKcyFDaL3e69JLg\",\"devSeq\":\"1\",\"version\":\"3.2.9\",\"language\":\"vi-vn\",\"isRoot\":\"false\",\"IpAddress\":\"103.63.114.42\",\"UniqueDeviceId\":\"a2a04ece-db28-353c-900f-5bc7cb8f56ed\",\"isNfcAvailable\":\"Y\"}"; // 注意：必须是服务端收到的确切 Header 字符串

const hash = createHashReqBody(reqBody, header);
console.log("Calculated Hash:", hash);