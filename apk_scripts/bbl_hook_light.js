Java.perform(function() {
    try {
        console.log("[*] Starting BBL Mobile Banking light hook");

        // Hook URL only
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            try {
                console.log("[+] URL: " + this.toString());
            } catch (e) {
                console.log("[!] Error in URL hook: " + e);
            }
            return this.openConnection();
        };

        // Hook HttpURLConnection
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function() {
            try {
                console.log("[+] Request: " + this.getRequestMethod() + " " + this.getURL().toString());
            } catch (e) {
                console.log("[!] Error in HttpURLConnection hook: " + e);
            }
            return this.getInputStream();
        };

        console.log("[*] BBL Mobile Banking light hook installed");
    } catch (e) {
        console.log("[!] Error in main hook: " + e);
    }
}); 