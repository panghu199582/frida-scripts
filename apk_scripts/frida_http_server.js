Java.perform(function() {
    // 创建一个简单的 HTTP 服务器
    var server = new java.net.ServerSocket(3000);
    console.log("[*] HTTP Server started on port 3000");

    // 处理请求的函数
    function handleRequest(socket) {
        try {
            var input = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream()));
            var output = new java.io.PrintWriter(socket.getOutputStream(), true);
            
            // 读取请求
            var request = input.readLine();
            console.log("[*] Received request: " + request);
            
            // 解析请求方法和路径
            var parts = request.split(" ");
            var method = parts[0];
            var path = parts[1];
            
            // 构建响应
            var response = "";
            if (method === "GET") {
                if (path === "/") {
                    response = "HTTP/1.1 200 OK\r\n" +
                             "Content-Type: application/json\r\n" +
                             "Access-Control-Allow-Origin: *\r\n" +
                             "\r\n" +
                             JSON.stringify({
                                 status: "success",
                                 message: "Frida HTTP Server is running!"
                             });
                } else if (path === "/info") {
                    // 获取应用信息
                    var packageName = Java.use("android.app.ActivityThread").currentApplication().getPackageName();
                    var versionName = Java.use("android.content.pm.PackageManager").getPackageInfo(packageName, 0).versionName;
                    
                    response = "HTTP/1.1 200 OK\r\n" +
                             "Content-Type: application/json\r\n" +
                             "Access-Control-Allow-Origin: *\r\n" +
                             "\r\n" +
                             JSON.stringify({
                                 packageName: packageName,
                                 versionName: versionName
                             });
                } else {
                    response = "HTTP/1.1 404 Not Found\r\n\r\n";
                }
            } else if (method === "POST") {
                // 读取 POST 数据
                var contentLength = 0;
                var line;
                while ((line = input.readLine()) != null && line.length() > 0) {
                    if (line.startsWith("Content-Length: ")) {
                        contentLength = parseInt(line.substring(16));
                    }
                }
                
                var postData = "";
                for (var i = 0; i < contentLength; i++) {
                    postData += String.fromCharCode(input.read());
                }
                
                console.log("[*] POST data: " + postData);
                
                response = "HTTP/1.1 200 OK\r\n" +
                         "Content-Type: application/json\r\n" +
                         "Access-Control-Allow-Origin: *\r\n" +
                         "\r\n" +
                         JSON.stringify({
                             status: "success",
                             received: postData
                         });
            } else {
                response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            }
            
            // 发送响应
            output.println(response);
            
        } catch (e) {
            console.log("[!] Error handling request: " + e);
        } finally {
            socket.close();
        }
    }

    // 启动服务器监听
    new Thread(function() {
        while (true) {
            try {
                var socket = server.accept();
                handleRequest(socket);
            } catch (e) {
                console.log("[!] Server error: " + e);
                break;
            }
        }
    }).start();

    // 注册一个全局函数，可以从外部调用
    global.handleCustomRequest = function(data) {
        console.log("[*] Custom request received: " + data);
        // 这里可以添加自定义的处理逻辑
        return {
            status: "success",
            message: "Custom request processed",
            data: data
        };
    };
}); 