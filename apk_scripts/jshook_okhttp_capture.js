Java.perform(function() {
    console.log("[+] OkHttp Network Capture Script Loaded");
    
    // Hook OkHttpClient - Main client class
    try {
        var OkHttpClient = Java.use("com.android.okhttp.OkHttpClient");
        console.log("[+] Found OkHttpClient class");
        
        // Hook newCall method
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[+] OkHttpClient.newCall() called");
            console.log("    Request URL: " + request.url().toString());
            console.log("    Request Method: " + request.method());
            
            // Log headers
            var headers = request.headers();
            if (headers) {
                console.log("    Request Headers:");
                for (var i = 0; i < headers.size(); i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    console.log("        " + name + ": " + value);
                }
            }
            
            // Log body if present
            var body = request.body();
            if (body) {
                console.log("    Request Body Type: " + body.contentType());
                console.log("    Request Body Length: " + body.contentLength());
            }
            
            var result = this.newCall(request);
            console.log("[+] OkHttpClient.newCall() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttpClient not found: " + e);
    }
    
    // Hook Request class
    try {
        var Request = Java.use("com.android.okhttp.Request");
        console.log("[+] Found Request class");
        
        Request.$init.overload('com.android.okhttp.Request$Builder').implementation = function(builder) {
            console.log("[+] Request constructor called");
            var result = this.$init(builder);
            
            try {
                console.log("    URL: " + this.url().toString());
                console.log("    Method: " + this.method());
                
                var headers = this.headers();
                if (headers) {
                    console.log("    Headers count: " + headers.size());
                }
                
                var body = this.body();
                if (body) {
                    console.log("    Body present: " + body.contentType());
                }
            } catch (e) {
                console.log("    Error getting request details: " + e);
            }
            
            return result;
        };
    } catch (e) {
        console.log("[-] Request class not found: " + e);
    }
    
    // Hook Response class
    try {
        var Response = Java.use("com.android.okhttp.Response");
        console.log("[+] Found Response class");
        
        Response.body.implementation = function() {
            var result = this.body();
            console.log("[+] Response.body() called");
            console.log("    Response Code: " + this.code());
            console.log("    Response Message: " + this.message());
            console.log("    Response URL: " + this.request().url().toString());
            
            // Log response headers
            var headers = this.headers();
            if (headers) {
                console.log("    Response Headers:");
                for (var i = 0; i < headers.size(); i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    console.log("        " + name + ": " + value);
                }
            }
            
            return result;
        };
    } catch (e) {
        console.log("[-] Response class not found: " + e);
    }
    
    // Hook HttpEngine - Core HTTP processing
    try {
        var HttpEngine = Java.use("com.android.okhttp.internal.http.HttpEngine");
        console.log("[+] Found HttpEngine class");
        
        HttpEngine.sendRequest.implementation = function() {
            console.log("[+] HttpEngine.sendRequest() called");
            var result = this.sendRequest();
            console.log("[+] HttpEngine.sendRequest() completed");
            return result;
        };
        
        HttpEngine.readResponse.implementation = function() {
            console.log("[+] HttpEngine.readResponse() called");
            var result = this.readResponse();
            console.log("[+] HttpEngine.readResponse() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] HttpEngine not found: " + e);
    }
    
    // Hook Http1xStream - HTTP/1.1 stream processing
    try {
        var Http1xStream = Java.use("com.android.okhttp.internal.http.Http1xStream");
        console.log("[+] Found Http1xStream class");
        
        Http1xStream.writeRequestHeaders.implementation = function(request) {
            console.log("[+] Http1xStream.writeRequestHeaders() called");
            console.log("    Request: " + request.url().toString());
            var result = this.writeRequestHeaders(request);
            console.log("[+] Http1xStream.writeRequestHeaders() completed");
            return result;
        };
        
        Http1xStream.readResponseHeaders.implementation = function() {
            console.log("[+] Http1xStream.readResponseHeaders() called");
            var result = this.readResponseHeaders();
            console.log("[+] Http1xStream.readResponseHeaders() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Http1xStream not found: " + e);
    }
    
    // Hook RealConnection - Actual connection handling
    try {
        var RealConnection = Java.use("com.android.okhttp.internal.io.RealConnection");
        console.log("[+] Found RealConnection class");
        
        RealConnection.connect.implementation = function(connectTimeout, readTimeout, writeTimeout, connectionRetryEnabled, call, eventListener) {
            console.log("[+] RealConnection.connect() called");
            console.log("    Connect Timeout: " + connectTimeout);
            console.log("    Read Timeout: " + readTimeout);
            console.log("    Write Timeout: " + writeTimeout);
            
            var result = this.connect(connectTimeout, readTimeout, writeTimeout, connectionRetryEnabled, call, eventListener);
            console.log("[+] RealConnection.connect() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] RealConnection not found: " + e);
    }
    
    // Hook HttpURLConnectionImpl - URLConnection implementation
    try {
        var HttpURLConnectionImpl = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
        console.log("[+] Found HttpURLConnectionImpl class");
        
        HttpURLConnectionImpl.connect.implementation = function() {
            console.log("[+] HttpURLConnectionImpl.connect() called");
            console.log("    URL: " + this.getURL().toString());
            console.log("    Method: " + this.getRequestMethod());
            
            var result = this.connect();
            console.log("[+] HttpURLConnectionImpl.connect() completed");
            return result;
        };
        
        HttpURLConnectionImpl.getInputStream.implementation = function() {
            console.log("[+] HttpURLConnectionImpl.getInputStream() called");
            var result = this.getInputStream();
            console.log("[+] HttpURLConnectionImpl.getInputStream() completed");
            return result;
        };
        
        HttpURLConnectionImpl.getOutputStream.implementation = function() {
            console.log("[+] HttpURLConnectionImpl.getOutputStream() called");
            var result = this.getOutputStream();
            console.log("[+] HttpURLConnectionImpl.getOutputStream() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] HttpURLConnectionImpl not found: " + e);
    }
    
    // Hook HttpsURLConnectionImpl - HTTPS URLConnection implementation
    try {
        var HttpsURLConnectionImpl = Java.use("com.android.okhttp.internal.huc.HttpsURLConnectionImpl");
        console.log("[+] Found HttpsURLConnectionImpl class");
        
        HttpsURLConnectionImpl.connect.implementation = function() {
            console.log("[+] HttpsURLConnectionImpl.connect() called");
            console.log("    URL: " + this.getURL().toString());
            console.log("    Method: " + this.getRequestMethod());
            
            var result = this.connect();
            console.log("[+] HttpsURLConnectionImpl.connect() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] HttpsURLConnectionImpl not found: " + e);
    }
    
    // Hook RequestBody - Request body handling
    try {
        var RequestBody = Java.use("com.android.okhttp.RequestBody");
        console.log("[+] Found RequestBody class");
        
        RequestBody.writeTo.implementation = function(sink) {
            console.log("[+] RequestBody.writeTo() called");
            console.log("    Content Type: " + this.contentType());
            console.log("    Content Length: " + this.contentLength());
            
            var result = this.writeTo(sink);
            console.log("[+] RequestBody.writeTo() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] RequestBody not found: " + e);
    }
    
    // Hook ResponseBody - Response body handling
    try {
        var ResponseBody = Java.use("com.android.okhttp.ResponseBody");
        console.log("[+] Found ResponseBody class");
        
        ResponseBody.string.implementation = function() {
            console.log("[+] ResponseBody.string() called");
            var result = this.string();
            console.log("    Response Body Length: " + result.length);
            console.log("    Response Body Preview: " + result.substring(0, Math.min(200, result.length)));
            console.log("[+] ResponseBody.string() completed");
            return result;
        };
        
        ResponseBody.bytes.implementation = function() {
            console.log("[+] ResponseBody.bytes() called");
            var result = this.bytes();
            console.log("    Response Body Bytes Length: " + result.length);
            console.log("[+] ResponseBody.bytes() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] ResponseBody not found: " + e);
    }
    
    // Hook Headers - Header handling
    try {
        var Headers = Java.use("com.android.okhttp.Headers");
        console.log("[+] Found Headers class");
        
        Headers.get.overload('java.lang.String').implementation = function(name) {
            var result = this.get(name);
            if (result) {
                console.log("[+] Headers.get() called: " + name + " = " + result);
            }
            return result;
        };
    } catch (e) {
        console.log("[-] Headers not found: " + e);
    }
    
    // Hook HttpUrl - URL parsing and building
    try {
        var HttpUrl = Java.use("com.android.okhttp.HttpUrl");
        console.log("[+] Found HttpUrl class");
        
        HttpUrl.parse.overload('java.lang.String').implementation = function(url) {
            console.log("[+] HttpUrl.parse() called: " + url);
            var result = this.parse(url);
            console.log("[+] HttpUrl.parse() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] HttpUrl not found: " + e);
    }
    
    // Hook Dispatcher - Request dispatching
    try {
        var Dispatcher = Java.use("com.android.okhttp.Dispatcher");
        console.log("[+] Found Dispatcher class");
        
        Dispatcher.enqueue.implementation = function(call) {
            console.log("[+] Dispatcher.enqueue() called");
            console.log("    Call: " + call.request().url().toString());
            
            var result = this.enqueue(call);
            console.log("[+] Dispatcher.enqueue() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Dispatcher not found: " + e);
    }
    
    // Hook Call - Individual request call
    try {
        var Call = Java.use("com.android.okhttp.Call");
        console.log("[+] Found Call class");
        
        Call.execute.implementation = function() {
            console.log("[+] Call.execute() called");
            console.log("    Request: " + this.request().url().toString());
            
            var result = this.execute();
            console.log("[+] Call.execute() completed");
            console.log("    Response Code: " + result.code());
            return result;
        };
    } catch (e) {
        console.log("[-] Call not found: " + e);
    }
    
    console.log("[+] OkHttp capture hooks installed successfully");
    console.log("[+] Monitoring all OkHttp network activity...");
}); 