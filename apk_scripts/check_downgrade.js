/*
 * Check Protocol Status
 * Inspects o.a constructor to see what protocols are being requested.
 */

Java.perform(function() {
    var TargetClass = Java.use("o.a");
    
    TargetClass.$init.overloads.forEach(function(ctor) {
        ctor.implementation = function() {
            var args = [].slice.call(arguments);
            var PROTO_INDEX = 9; // Based on your JADX analysis

            if (args.length > PROTO_INDEX) {
                var list = args[PROTO_INDEX];
                if (list) {
                    var javaList = Java.cast(list, Java.use("java.util.List"));
                    console.log("\n[?] o.a Initialized with Protocols: " + javaList.toString());
                }
            }
            return this.$init.apply(this, args);
        }
    });

    console.log("[*] Monitoring o.a creation...");
});
