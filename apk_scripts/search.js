// 在脚本开头添加类搜索
Java.perform(function() {
  // 搜索所有包含"okhttp"的类
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      if (className.toLowerCase().includes("okhttp")) {
        console.log("[!] Found possible OkHttp class: " + className);
      }
    },
    onComplete: function() {}
  });
});