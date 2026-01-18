if (ObjC.available) {
    try {
        console.log('[*] Starting network monitoring...');
        
        var pendingBlocks = {};
        var blockId = 0;

        // Helper to process response headers
        function processHeaders(response) {
            var headers = {};
            if (response && response.allHeaderFields) {
                var allHeaderFields = response.allHeaderFields();
                if (allHeaderFields) {
                    var keys = allHeaderFields.allKeys();
                    var count = keys.count();
                    for (var i = 0; i < count; i++) {
                        var key = keys.objectAtIndex_(i);
                        var value = allHeaderFields.objectForKey_(key);
                        if (key && value) {
                            headers[key.toString()] = value.toString();
                        }
                    }
                }
            }
            return headers;
        }

        // Helper to process response data
        function processData(data) {
            if (!data) return '';
            try {
                var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                return str ? str.toString() : '[Binary Data]';
            } catch(e) {
                return '[Binary Data]';
            }
        }

        // Monitor NSURLSession
        try {
            var URLSession = ObjC.classes.NSURLSession;
            if (URLSession) {
                Interceptor.attach(URLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
                    onEnter: function(args) {
                        var request = args[2];
                        var origBlock = new ObjC.Block(args[3]);
                        
                        var id = blockId++;
                        pendingBlocks[id] = origBlock;
                        
                        var newBlock = new ObjC.Block({
                            retType: 'void',
                            argTypes: ['object', 'object', 'object'],
                            implementation: function(data, response, error) {
                                try {
                                    if (response) {
                                        console.log(JSON.stringify({
                                            'url': request.URL().absoluteString().toString(),
                                            'method': request.HTTPMethod().toString(),
                                            'headers': processHeaders(response),
                                            'statusCode': response.statusCode(),
                                            'body': processData(data),
                                            'timestamp': new Date().toISOString()
                                        }, null, 2));
                                    }
                                } catch(e) {
                                    console.log('[-] Error processing response:', e.message);
                                }
                                
                                var origCompletionHandler = pendingBlocks[id];
                                if (origCompletionHandler) {
                                    origCompletionHandler.implementation(data, response, error);
                                    delete pendingBlocks[id];
                                }
                            }
                        });
                        
                        args[3] = newBlock;
                    }
                });
                
                console.log('[+] Successfully hooked NSURLSession');
            }
        } catch(e) {
            console.log('[-] Error hooking NSURLSession:', e.message);
        }

        // Monitor NSURLConnection
        try {
            var URLConnection = ObjC.classes.NSURLConnection;
            if (URLConnection) {
                Interceptor.attach(URLConnection["+ sendSynchronousRequest:returningResponse:error:"].implementation, {
                    onEnter: function(args) {
                        this.request = args[2];
                    },
                    onLeave: function(retval) {
                        if (this.request) {
                            try {
                                console.log(JSON.stringify({
                                    'url': this.request.URL().absoluteString().toString(),
                                    'method': this.request.HTTPMethod().toString(),
                                    'timestamp': new Date().toISOString()
                                }, null, 2));
                            } catch(e) {
                                console.log('[-] Error processing URLConnection:', e.message);
                            }
                        }
                    }
                });
                
                console.log('[+] Successfully hooked NSURLConnection');
            }
        } catch(e) {
            console.log('[-] Error hooking NSURLConnection:', e.message);
        }

        console.log('[+] Network monitoring setup complete');
        
    } catch(e) {
        console.log('[-] Error setting up hooks:', e.message);
    }
} else {
    console.log('[-] Objective-C Runtime is not available!');
}