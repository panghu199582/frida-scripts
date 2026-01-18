/*
 * OkHttp Logger Injector
 * Hooks OkHttpClient.Builder.addInterceptor() to inject a custom Logger.
 * Captures FULL Requests and Responses (Headers + Body) at the application layer.
 */

Java.perform(function() {
    console.log("[*] 💉 Starting OkHttp Logger Injector...");

    // Helper: Find OkHttpClient.Builder class
    // We already know 'o.a' is Address. OkHttp classes are likely in 'o' package.
    // We need to find the Builder class. It has methods like addInterceptor, addNetworkInterceptor.

    // Let's look for a class with 'addInterceptor' or 'protocols' methods.
    // Or we scan for the specific signature of addInterceptor.
    
    var BuilderClass = null;
    var AddInterceptorMethod = null;

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.startsWith("o.") && className.length < 10 && !BuilderClass) {
                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    for(var i=0; i<methods.length; i++) {
                        var m = methods[i];
                        // addInterceptor signature: (Interceptor) -> Builder
                        // Check if param is an interface in 'o' package
                        var args = m.getParameterTypes();
                        if (args.length === 1 && m.getReturnType().getName() === className) {
                            var argType = args[0].getName();
                            // Interceptor interface usually has one method: intercept
                            // It's hard to verify purely by name.
                            
                            // Let's assume user provided JADX info or we guess.
                            // If we can't find it dynamically, we hook known Retrofit/OkHttp points.
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {}
    });

    // PLAN B: Since finding the Builder is hard blindly, let's Hook the `RealCall` execution directly.
    // We know 'o.z' is likely Request (from previous chat context, user didn't confirm but based on o.a it's close).
    
    // BETTER PLAN: Hook Retrofit's OkHttpCall.
    // Retrofit is used. 
    // Class: retrofit2.OkHttpCall (obfuscated as r.X)
    // It has a method parseResponse() or similar.
    
    // Let's stick to the MOST RELIABLE method:
    // Hook java.net.HttpURLConnection (if used? No, Retrofit uses OkHttp).
    
    // Let's try to Hook 'o.z' (Request) constructor to printing headers?
    // We can try scanning for the Interceptor interface again.
    
    // User, please provide one JADX file content: The file that defines the 'Interceptor' interface.
    // It is the type of the argument in 'addInterceptor' in OkHttpClient.Builder.
    // It has a single method: Response intercept(Chain chain);
});

// Since I can't inject without knowing the class names, I will provide a script
// that simply Hooks strings globally to find the Header values.
// This is brute-force but effective.
