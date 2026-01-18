Java.perform(function() {
    console.log("[+] OkHttp3 & Okio Network Capture Script Loaded");
    
    // Helper function to convert byte array to hex string
    function bytes2hex(bytes) {
        var result = '';
        for (var i = 0; i < bytes.length; i++) {
            var hex = (bytes[i] & 0xFF).toString(16);
            if (hex.length === 1) {
                hex = '0' + hex;
            }
            result += hex;
        }
        return result;
    }
    
    // Hook OkHttp3Client - Main client class
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        console.log("[+] Found OkHttp3Client class");
        
        // Hook newCall method
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[+] OkHttp3Client.newCall() called");
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
            console.log("[+] OkHttp3Client.newCall() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3Client not found: " + e);
    }
    
    // Hook OkHttp3 Request class
    try {
        var Request = Java.use("okhttp3.Request");
        console.log("[+] Found OkHttp3 Request class");
        
        Request.$init.overload('okhttp3.Request$Builder').implementation = function(builder) {
            console.log("[+] OkHttp3 Request constructor called");
            var result = this.$init(builder);
            
            try {
                console.log("    URL: " + this.url().toString());
                console.log("    Method: " + this.method());
                
                var headers = this.headers();
                if (headers) {
                    console.log("    Headers count: " + headers.size());
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        console.log("        " + name + ": " + value);
                    }
                }
                
                var body = this.body();
                if (body) {
                    console.log("    Body present: " + body.contentType());
                    console.log("    Body length: " + body.contentLength());
                }
            } catch (e) {
                console.log("    Error getting request details: " + e);
            }
            
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 Request class not found: " + e);
    }
    
    // Hook OkHttp3 Response class
    try {
        var Response = Java.use("okhttp3.Response");
        console.log("[+] Found OkHttp3 Response class");
        
        Response.body.implementation = function() {
            var result = this.body();
            console.log("[+] OkHttp3 Response.body() called");
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
        console.log("[-] OkHttp3 Response class not found: " + e);
    }
    
    // Hook OkHttp3 Call - Individual request call
    try {
        var Call = Java.use("okhttp3.Call");
        console.log("[+] Found OkHttp3 Call class");
        
        Call.execute.implementation = function() {
            console.log("[+] OkHttp3 Call.execute() called");
            console.log("    Request: " + this.request().url().toString());
            
            var result = this.execute();
            console.log("[+] OkHttp3 Call.execute() completed");
            console.log("    Response Code: " + result.code());
            return result;
        };
        
        Call.enqueue.implementation = function(callback) {
            console.log("[+] OkHttp3 Call.enqueue() called");
            console.log("    Request: " + this.request().url().toString());
            
            var result = this.enqueue(callback);
            console.log("[+] OkHttp3 Call.enqueue() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 Call not found: " + e);
    }
    
    // Hook OkHttp3 RequestBody - Request body handling
    try {
        var RequestBody = Java.use("okhttp3.RequestBody");
        console.log("[+] Found OkHttp3 RequestBody class");
        
        RequestBody.writeTo.implementation = function(sink) {
            console.log("[+] OkHttp3 RequestBody.writeTo() called");
            console.log("    Content Type: " + this.contentType());
            console.log("    Content Length: " + this.contentLength());
            
            // Create a buffer to capture the body content
            try {
                var Buffer = Java.use("okio.Buffer");
                var buffer = Buffer.$new();
                this.writeTo(buffer);
                
                // Try to read as string if possible
                try {
                    var bodyString = buffer.readString(Java.use("java.nio.charset.Charset").forName("UTF-8"));
                    console.log("    Request Body Content: " + bodyString);
                } catch (e) {
                    // If string reading fails, show as hex
                    var bytes = buffer.readByteArray();
                    console.log("    Request Body Bytes Length: " + bytes.length);
                    console.log("    Request Body Hex Preview: " + bytes2hex(bytes).substring(0, 200));
                }
            } catch (e) {
                console.log("    Error capturing request body: " + e);
            }
            
            var result = this.writeTo(sink);
            console.log("[+] OkHttp3 RequestBody.writeTo() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 RequestBody not found: " + e);
    }
    
    // Hook OkHttp3 ResponseBody - Response body handling
    try {
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        console.log("[+] Found OkHttp3 ResponseBody class");
        
        ResponseBody.string.implementation = function() {
            console.log("[+] OkHttp3 ResponseBody.string() called");
            var result = this.string();
            console.log("    Response Body Length: " + result.length);
            console.log("    Response Body Preview: " + result.substring(0, Math.min(200, result.length)));
            console.log("[+] OkHttp3 ResponseBody.string() completed");
            return result;
        };
        
        ResponseBody.bytes.implementation = function() {
            console.log("[+] OkHttp3 ResponseBody.bytes() called");
            var result = this.bytes();
            console.log("    Response Body Bytes Length: " + result.length);
            console.log("[+] OkHttp3 ResponseBody.bytes() completed");
            return result;
        };
        
        ResponseBody.byteStream.implementation = function() {
            console.log("[+] OkHttp3 ResponseBody.byteStream() called");
            var result = this.byteStream();
            console.log("[+] OkHttp3 ResponseBody.byteStream() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 ResponseBody not found: " + e);
    }
    
    // Hook OkHttp3 Headers - Header handling
    try {
        var Headers = Java.use("okhttp3.Headers");
        console.log("[+] Found OkHttp3 Headers class");
        
        Headers.get.overload('java.lang.String').implementation = function(name) {
            var result = this.get(name);
            if (result) {
                console.log("[+] OkHttp3 Headers.get() called: " + name + " = " + result);
            }
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 Headers not found: " + e);
    }
    
    // Hook OkHttp3 HttpUrl - URL parsing and building
    try {
        var HttpUrl = Java.use("okhttp3.HttpUrl");
        console.log("[+] Found OkHttp3 HttpUrl class");
        
        HttpUrl.parse.overload('java.lang.String').implementation = function(url) {
            console.log("[+] OkHttp3 HttpUrl.parse() called: " + url);
            var result = this.parse(url);
            console.log("[+] OkHttp3 HttpUrl.parse() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 HttpUrl not found: " + e);
    }
    
    // Hook OkHttp3 Dispatcher - Request dispatching
    try {
        var Dispatcher = Java.use("okhttp3.Dispatcher");
        console.log("[+] Found OkHttp3 Dispatcher class");
        
        Dispatcher.enqueue.implementation = function(call) {
            console.log("[+] OkHttp3 Dispatcher.enqueue() called");
            console.log("    Call: " + call.request().url().toString());
            
            var result = this.enqueue(call);
            console.log("[+] OkHttp3 Dispatcher.enqueue() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] OkHttp3 Dispatcher not found: " + e);
    }
    
    // Hook Okio classes - I/O operations
    try {
        var Buffer = Java.use("okio.Buffer");
        console.log("[+] Found Okio Buffer class");
        
        Buffer.writeString.implementation = function(string, charset) {
            console.log("[+] Okio Buffer.writeString() called");
            console.log("    String: " + string.substring(0, Math.min(100, string.length)));
            console.log("    Charset: " + charset);
            
            var result = this.writeString(string, charset);
            console.log("[+] Okio Buffer.writeString() completed");
            return result;
        };
        
        Buffer.readString.implementation = function(charset) {
            console.log("[+] Okio Buffer.readString() called");
            console.log("    Charset: " + charset);
            
            var result = this.readString(charset);
            console.log("    Read String: " + result.substring(0, Math.min(100, result.length)));
            console.log("[+] Okio Buffer.readString() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Okio Buffer not found: " + e);
    }
    
    // Hook Okio RealBufferedSink - Buffered output
    try {
        var RealBufferedSink = Java.use("okio.RealBufferedSink");
        console.log("[+] Found Okio RealBufferedSink class");
        
        RealBufferedSink.writeString.implementation = function(string, charset) {
            console.log("[+] Okio RealBufferedSink.writeString() called");
            console.log("    String: " + string.substring(0, Math.min(100, string.length)));
            console.log("    Charset: " + charset);
            
            var result = this.writeString(string, charset);
            console.log("[+] Okio RealBufferedSink.writeString() completed");
            return result;
        };
        
        RealBufferedSink.write.overload('[B').implementation = function(data) {
            console.log("[+] Okio RealBufferedSink.write() called");
            console.log("    Data Length: " + data.length);
            console.log("    Data Preview: " + Java.use("java.util.Arrays").toString(data).substring(0, 100));
            
            var result = this.write(data);
            console.log("[+] Okio RealBufferedSink.write() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Okio RealBufferedSink not found: " + e);
    }
    
    // Hook Okio RealBufferedSource - Buffered input
    try {
        var RealBufferedSource = Java.use("okio.RealBufferedSource");
        console.log("[+] Found Okio RealBufferedSource class");
        
        RealBufferedSource.readString.implementation = function(charset) {
            console.log("[+] Okio RealBufferedSource.readString() called");
            console.log("    Charset: " + charset);
            
            var result = this.readString(charset);
            console.log("    Read String: " + result.substring(0, Math.min(100, result.length)));
            console.log("[+] Okio RealBufferedSource.readString() completed");
            return result;
        };
        
        RealBufferedSource.read.overload('[B').implementation = function(sink) {
            console.log("[+] Okio RealBufferedSource.read() called");
            console.log("    Sink Length: " + sink.length);
            
            var result = this.read(sink);
            console.log("    Read Bytes: " + result);
            console.log("[+] Okio RealBufferedSource.read() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Okio RealBufferedSource not found: " + e);
    }
    
    // Hook Okio Okio - Utility class
    try {
        var Okio = Java.use("okio.Okio");
        console.log("[+] Found Okio Okio class");
        
        Okio.source.overload('java.io.InputStream').implementation = function(input) {
            console.log("[+] Okio.source(InputStream) called");
            var result = this.source(input);
            console.log("[+] Okio.source(InputStream) completed");
            return result;
        };
        
        Okio.sink.overload('java.io.OutputStream').implementation = function(output) {
            console.log("[+] Okio.sink(OutputStream) called");
            var result = this.sink(output);
            console.log("[+] Okio.sink(OutputStream) completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Okio Okio not found: " + e);
    }
    
    // Hook Retrofit classes if present
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        console.log("[+] Found Retrofit class");
        
        Retrofit.create.implementation = function(service) {
            console.log("[+] Retrofit.create() called");
            console.log("    Service: " + service.getName());
            
            var result = this.create(service);
            console.log("[+] Retrofit.create() completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Retrofit not found: " + e);
    }
    
    // Hook Volley classes if present
    try {
        var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
        console.log("[+] Found Volley StringRequest class");
        
        StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
            console.log("[+] Volley StringRequest constructor called");
            console.log("    Method: " + method);
            console.log("    URL: " + url);
            
            var result = this.$init(method, url, listener, errorListener);
            console.log("[+] Volley StringRequest constructor completed");
            return result;
        };
    } catch (e) {
        console.log("[-] Volley StringRequest not found: " + e);
    }
    
    console.log("[+] OkHttp3 & Okio capture hooks installed successfully");
    console.log("[+] Monitoring all modern network library activity...");
}); 