Java.perform(function() {
    // 拦截 OkHttpClient 的请求
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var MediaType = Java.use('okhttp3.MediaType');
    var Buffer = Java.use('okio.Buffer');

    // tmxSessionId 生成器
    var TmxSessionGenerator = Java.use('com.threatmetrix.TrustDefenderMobile.TMXProfiling');
    var tmxSessionId = null;

    // Hook newCall 方法
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        var method = request.method();
        var headers = request.headers();
        var body = request.body();

        // 检查是否是 PIN 相关的请求
        if (url.includes('/api/v1/registration/authentication/id') || 
            url.includes('/api/v1/registration/authentication/pin')) {
            
            console.log('\n=== 拦截到 BBL PIN 请求 ===');
            console.log('URL:', url);
            console.log('Method:', method);
            console.log('Headers:', headers.toString());

            // 如果有请求体，打印出来
            if (body) {
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                var bodyString = buffer.readUtf8();
                console.log('Body:', bodyString);

                // 解析 JSON 请求体
                try {
                    var jsonBody = JSON.parse(bodyString);
                    
                    // 如果存在 tmxSessionId，保存它
                    if (jsonBody.tmxSessionId) {
                        tmxSessionId = jsonBody.tmxSessionId;
                        console.log('保存的 tmxSessionId:', tmxSessionId);
                    }
                } catch (e) {
                    console.log('解析请求体失败:', e);
                }
            }

            // 存储请求信息到本地
            var requestInfo = {
                url: url,
                method: method,
                headers: headers.toString(),
                body: body ? bodyString : null,
                timestamp: new Date().toISOString()
            };

            // 将请求信息发送到本地服务器
            sendToLocalServer(requestInfo);
        }

        // 继续执行原始请求
        return this.newCall(request);
    };

    // 发送请求信息到本地服务器
    function sendToLocalServer(requestInfo) {
        try {
            var URL = Java.use('java.net.URL');
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            var OutputStreamWriter = Java.use('java.io.OutputStreamWriter');
            var BufferedReader = Java.use('java.io.BufferedReader');
            var InputStreamReader = Java.use('java.io.InputStreamReader');

            var url = new URL('http://localhost:3000');
            var connection = url.openConnection();
            connection.setRequestMethod('POST');
            connection.setRequestProperty('Content-Type', 'application/json');
            connection.setDoOutput(true);

            var writer = new OutputStreamWriter(connection.getOutputStream());
            writer.write(JSON.stringify(requestInfo));
            writer.flush();
            writer.close();

            var responseCode = connection.getResponseCode();
            console.log('发送到本地服务器状态码:', responseCode);

            var reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            var response = '';
            var line;
            while ((line = reader.readLine()) != null) {
                response += line;
            }
            reader.close();
            console.log('本地服务器响应:', response);

        } catch (e) {
            console.log('发送到本地服务器失败:', e);
        }
    }

    // Hook TMXProfiling 的 getSessionID 方法
    if (TmxSessionGenerator) {
        TmxSessionGenerator.getSessionID.implementation = function() {
            var originalSessionId = this.getSessionID();
            console.log('原始 tmxSessionId:', originalSessionId);
            
            // 如果已经保存了 tmxSessionId，使用保存的
            if (tmxSessionId) {
                console.log('使用保存的 tmxSessionId:', tmxSessionId);
                return tmxSessionId;
            }
            
            return originalSessionId;
        };
    }
}); 