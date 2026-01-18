/*
 * Heap Scanner for OkHttp Requests
 * Safe & Passive: Scans memory for Request-like objects and prints their headers.
 * Does not hook methods, so no freeze.
 */

Java.perform(function() {
    console.log("[*] Scanning heap for Request objects...");

    // Common obfuscated field names for Request:
    // headers (Headers), url (HttpUrl), method (String), body (RequestBody)
    
    // We scan for instances of "o.z" or "o.y" or similar (based on neighbors of o.a)
    // Or we scan for any class that holds a "headers" field.

    Java.choose("o.z", { // Try scanning common name, or replace scanning logic
        onMatch: function(instance) {
             console.log("[?] Found instance of o.z");
             // try to print it
             try { console.log("    " + instance.toString()); } catch(e){}
        },
        onComplete: function() {}
    });

    // Strategy 2: Scan for Header Builder
    // Headers.Builder usually holds a List text list.
    
});

// Since we don't know the class name, let's look for "Headers" class first.
// Headers class matches:
// 1. Validating method signatures in JADX is best.
// 2. But we can Try:
// Hooking java.util.ArrayList.add() ? No, too noisy.

// Let's rely on your JADX info.
// Please paste content of 'o.a0' or 'o.y' or 'o.z' files here if you have them.
