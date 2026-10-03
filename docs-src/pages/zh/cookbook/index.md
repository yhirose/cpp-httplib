---
title: "实用示例"
order: 0
status: "draft"
---

一组回答“我该怎么做……？”这类问题的实用示例。每个示例都自成一体 —— 只读你需要的部分即可。基础入门请参阅[导览](../tour/)。

## 客户端

### 基础
- [C01. 获取响应体 / 保存到文件](c01-get-response-body)
- [C02. 发送和接收 JSON](c02-json)
- [C03. 设置默认请求头](c03-default-headers)
- [C04. 跟随重定向](c04-follow-location)

### 认证
- [C05. 使用 Basic 认证](c05-basic-auth)
- [C06. 使用 Bearer token 调用 API](c06-bearer-token)

### 文件上传
- [C07. 以 multipart 表单数据上传文件](c07-multipart-upload)
- [C08. 以原始二进制 POST 文件](c08-post-file-body)
- [C09. 使用 chunked 传输发送请求体](c09-chunked-upload)

### 流式传输与进度
- [C10. 以流的方式接收响应](c10-stream-response)
- [C11. 使用进度回调](c11-progress-callback)

### 连接与性能
- [C12. 设置超时](c12-timeouts)
- [C13. 设置整体超时](c13-max-timeout)
- [C14. 理解连接复用与 Keep-Alive 行为](c14-keep-alive)
- [C15. 启用压缩](c15-compression)
- [C16. 通过代理发送请求](c16-proxy)

### 错误处理与调试
- [C17. 处理错误码](c17-error-codes)
- [C18. 处理 SSL 错误](c18-ssl-errors)
- [C19. 设置客户端日志](c19-client-logger)

## 服务器

### 基础
- [S01. 注册 GET / POST / PUT / DELETE 处理器](s01-handlers)
- [S02. 接收 JSON 请求并返回 JSON 响应](s02-json-api)
- [S03. 使用路径参数](s03-path-params)
- [S04. 搭建静态文件服务器](s04-static-files)

### 流式传输与文件
- [S05. 在响应中流式传输大文件](s05-stream-response)
- [S06. 返回文件下载响应](s06-download-response)
- [S07. 以流的方式接收 multipart 数据](s07-multipart-reader)
- [S08. 返回压缩后的响应](s08-compress-response)

### 处理器链
- [S09. 为所有路由添加预处理](s09-pre-routing)
- [S10. 使用后置路由处理器添加响应头](s10-post-routing)
- [S11. 使用前置请求处理器按路由进行认证](s11-pre-request)
- [S12. 使用 `res.user_data` 在处理器之间传递数据](s12-user-data)

### 错误处理与调试
- [S13. 返回自定义错误页面](s13-error-handler)
- [S14. 捕获异常](s14-exception-handler)
- [S15. 记录请求日志](s15-server-logger)
- [S16. 检测客户端断开连接](s16-disconnect)

### 运维与调优
- [S17. 绑定到任意可用端口](s17-bind-any-port)
- [S18. 使用 `listen_after_bind` 控制启动顺序](s18-listen-after-bind)
- [S19. 优雅关闭](s19-graceful-shutdown)
- [S20. 调优 Keep-Alive](s20-keep-alive)
- [S21. 配置线程池](s21-thread-pool)
- [S22. 通过 Unix 域套接字通信](s22-unix-socket)

### 协议扩展
- [S23. 处理自定义 HTTP 方法](s23-custom-methods)

## TLS / 安全

- [T01. 在 OpenSSL、mbedTLS 和 wolfSSL 之间做选择](t01-tls-backends)
- [T02. 控制 SSL 证书验证](t02-cert-verification)
- [T03. 启动 SSL/TLS 服务器](t03-ssl-server)
- [T04. 配置 mTLS](t04-mtls)
- [T05. 在服务器上访问对端证书](t05-peer-cert)

## SSE

- [E01. 实现 SSE 服务器](e01-sse-server)
- [E02. 在 SSE 中使用命名事件](e02-sse-event-names)
- [E03. 处理 SSE 重连](e03-sse-reconnect)
- [E04. 在客户端接收 SSE](e04-sse-client)

## WebSocket

- [W01. 实现 WebSocket 回显服务器和客户端](w01-websocket-echo)
- [W02. 设置 WebSocket 心跳](w02-websocket-ping)
- [W03. 处理连接关闭](w03-websocket-close)
- [W04. 发送和接收二进制帧](w04-websocket-binary)
- [W05. 为 wss:// 连接配置 TLS](w05-websocket-tls)
- [W06. 设置超时](w06-websocket-timeouts)
