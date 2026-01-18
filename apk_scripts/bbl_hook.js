Java.perform(function() {
    try {
        console.log("[*] Starting BBL Mobile Banking hook");

        // Hook OkHttpClient
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var RequestBody = Java.use('okhttp3.RequestBody');
        var Buffer = Java.use('okio.Buffer');

        // Hook newCall method with try-catch
        OkHttpClient.newCall.implementation = function(request) {
            try {
                console.log("[+] Intercepted request:");
                console.log("    URL: " + request.url().toString());
                console.log("    Method: " + request.method());
                
                // Log headers
                var headers = request.headers();
                var headerNames = headers.names();
                console.log("    Headers:");
                for (var i = 0; i < headerNames.size(); i++) {
                    var name = headerNames.get(i);
                    console.log("        " + name + ": " + headers.get(name));
                }

                // Log request body if exists
                var body = request.body();
                if (body) {
                    try {
                        var buffer = Buffer.$new();
                        body.writeTo(buffer);
                        console.log("    Body: " + buffer.readUtf8());
                    } catch (e) {
                        console.log("    Body: [Error reading body]");
                    }
                }
            } catch (e) {
                console.log("[!] Error in request hook: " + e);
            }
            return this.newCall(request);
        };

        // Hook Response with try-catch
        var Response = Java.use('okhttp3.Response');
        Response.body.overload().implementation = function() {
            try {
                var response = this.body();
                if (response) {
                    try {
                        var bodyString = response.string();
                        console.log("[+] Response body: " + bodyString);
                    } catch (e) {
                        console.log("[!] Error reading response body: " + e);
                    }
                }
                return response;
            } catch (e) {
                console.log("[!] Error in response hook: " + e);
                return this.body();
            }
        };

        console.log("[*] BBL Mobile Banking hook installed");
    } catch (e) {
        console.log("[!] Error in main hook: " + e);
    }
}); 