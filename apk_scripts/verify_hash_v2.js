const crypto = require('crypto');

// 1. The Encrypted Body (from your log)
const reqBodyBase64 = "1y8fLGKnzixNHadTT69Kuy5D3a3fEn/EcWQI8yr55B5pOkelZMw6+30S36kQz9w7CdV2UsSoZAfkopc7jfhN8hb4aUk61PgHGLTca3OaJweS2JA5leWqM+0sAtZTZpUPZzvG1lS648fNq47nMwvDnJ+atw14jWt1ZNbHBXaTFbX3AtLlfbuKIo5BT9BUhfFQLEyeLqlLd6o5VyZlBwBwZjjlIXo3D68GuEmDz53d8Z4uzu+nuZpQ9x+wpbHDVcUktTUNQEwAKdA5qDxrrqU8VwbSNNURucjYeSk/abuXq0Q5L5uZLph9UZfGCF508OKoOpoL+ZFhqkDSB45YvPWDiKtLHBVwZOhGXA2UMcL3h9YWw35/fBZAtaGeEik5rnh4lekawnW1aFJn0zPn5gCJDODIvesi0auO9HtIWMDKbGdKmkXW9NosJPCX7xo1Mx95FZO8q6+YCe+tfScVf28xF2D7dpIYEI9YsJ/YULX+eh6TVSLCIZygvYnAnK2Kd2RzE4sVHzunKKh7U0ttPAD9AZkLPAHESk2n8PxJPY/u55lXEyDSgp8G3c1BS9rVb9iD6sJCjkDncDesasp7ZxPnqfB4fcA81wtRAlOIk/LFDP4NcUxGoHr1dUAYzrS3JzzU6mILALmGCBxMESVBiKzi02Z7VB5Yodck4AnoDSoRMTkz0CZSwck0DwnVPytr0tuI4YPZGhfsuIvhqlibGnwIWRgSsKF8af3+YUvai3+PtrtwJNXJ0O5Rp4nyikLJ9MxOuG11FMJzgSVL8h3T7mj3H90ImSu+KhLcaBmkEYQ3lH0aJ290ycbig+ApL9ndjz1F3Hn4yZi9E7INMWg8MVPeb2C7pw8UyFG/p2Kep/pOCpLj43TV1+Oj3AEusgEMn52PJkbsDOU8WIXvmijAliVTcsODYIUPixB6zeb6FrRV2Lvh6KH3obyGcRrgVnhFEHXPqNXu0zIG774sWk4McCLHqtUEgRR2CFr3L1V9BUdAh1ZW2vtoj8nsKIJrIFu+FwBWZV36BxQnpuboDcnUx5hQs02U0vQRqbv8uVVavIsSd3Rghxv7Qvb1sIhs5eiosSI2JhNpG6PC0v+M6fFGQ/gu+f3yeD5CdsxveuBgkXUxJ8TXPq5P/yk6uI/2nu+yzzC9lTS8OHOsTBJ3EZdqkjJ7w7E2YuHzPHWTVP69MDdLsS9mddU8sSmhI8dOybXVyk7hgLeiMWHA6NjS38xooBib0QmCCNyFjY/Rf2UMva7jUnLl5EjGUbSSE8i7n33otYm8djlauN4ha/nxtOIwjTTGWbrk7wZqMV1idyrMbVEiC3UyN9pVn0EDszLF/9wIUNq4y2PxKdKsLCsGAuQowd6nBzncBo8Jq+a0pS9/Oi7cSCY90rJeSEkrtkhAv89YK9EZszMhMNE9gKLhahYXR9fnkgdM484z9lrgMnlf8ctTpsqQhT8w0m8SDIWDqwaSpnmKMg60l8bOc+sFekikmJ\/cB45skNxzUukYneC6ZjkqxYcF15Mw0NAzMc7tGdy7I2jrs5IrRc7wkVYxKcNr1DeT3PKOzyRNl9y8c6lMht6RmJfR7AljSZ9OPRg4xrYrTTH13s9d46UwYg9V2dJ678UHX9Vi8KFi21ZBFtijJBRj4iCqJRUCuyiNBeG341HL6ucBFf/ak+B6yfY4VVRWNy8wMpalBLPwMjJCK/2A877Tf82PYTbxL4bj7dG3sszNTSAigNpn7COyU8fq652F1DHIn9qy6dPOpDkTa4c1Z/apJ5KvCAdnFOCI0FnoxYdq2/2I+ewVLDeTzImb4byIYxhuVF5XU5/dMtv368q85XdlA4jqF+Oydg36Wm024SzK/lUqyPKzNtGdc8aq1WK2vDZHPeBm2MJ1o8ZgWPN0l/Fk0/2kHGnCU/ZZ0XaZlbj4m99qK1nVDUAXQcKjcdiPWlfc/m/R0efZWcXIs88YWtVLCB0=";

// 2. The Target Hash (from your log)
const targetHashBase64 = "cB4c05DHOAjX3G2SbIAseh6Z0Kve/jQPdoE3OXafX40=";

// 3. Other potential ingredients
const deviceId = "a2a04ece-db28-353c-900f-5bc7cb8f56ed";

function tryHash(input, label) {
    const hash = crypto.createHash('sha256').update(input).digest('base64');
    console.log(`[${label}] Result: ${hash}`);
    if (hash === targetHashBase64) {
        console.log(`✅ MATCH FOUND! Input was: ${label}`);
        return true;
    }
    return false;
}

console.log("--- Verifying Hash Logic ---");
console.log("Target: " + targetHashBase64);

// Attempt 1: Just ReqBody
tryHash(reqBodyBase64, "ReqBody");

// Attempt 2: ReqBody + DeviceID (Common pattern)
tryHash(reqBodyBase64 + deviceId, "ReqBody + DeviceID");
tryHash(deviceId + reqBodyBase64, "DeviceID + ReqBody");

// Attempt 3: Just the hashReqBody string itself (sometimes logs are weird)
// Unlikely.

// Attempt 4: Maybe the input was the JSON string of ReqBody?
// i.e. "{\"devSeq\":52...}"
// We don't have the original plaintext easily here without decoding, 
// unless we use the '1y8f...' which IS the result of encryption.

console.log("--- End ---");
