const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const port = 3000;

// 启用 CORS
app.use(cors());

// 解析 JSON 请求体
app.use(bodyParser.json());

// 存储拦截到的请求
let interceptedRequests = [];

// 拦截所有 POST 请求
app.post('*', (req, res) => {
    // 打印请求信息
    console.log('\n=== 拦截到新请求 ===');
    console.log('URL:', req.url);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body:', JSON.stringify(req.body, null, 2));
    
    // 存储请求信息
    interceptedRequests.push({
        url: req.url,
        headers: req.headers,
        body: req.body,
        timestamp: new Date().toISOString()
    });
    
    // 返回成功响应，但不转发请求
    res.status(200).json({
        message: '请求已拦截',
        requestId: interceptedRequests.length
    });
});

// 获取所有拦截到的请求
app.get('/intercepted', (req, res) => {
    res.json(interceptedRequests);
});

// 清除所有拦截的请求
app.delete('/intercepted', (req, res) => {
    interceptedRequests = [];
    res.json({ message: '已清除所有拦截的请求' });
});

app.listen(port, () => {
    console.log(`代理服务器运行在 http://localhost:${port}`);
    console.log('等待拦截请求...');
}); 