---
title: "WebSocket"
order: 8
---

cpp-httplibはWebSocketにも対応しています。HTTPのリクエスト/レスポンスと違い、WebSocketはサーバーとクライアントが双方向にメッセージをやり取りできます。チャットやリアルタイム通知に便利です。

さっそく、エコーサーバーとクライアントを作ってみましょう。

## エコーサーバー

受け取ったメッセージをそのまま返すエコーサーバーです。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
        std::string msg;
        while (ws.read(msg)) {
            ws.send(msg);  // 受け取ったメッセージをそのまま返す
        }
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

`svr.WebSocket()` でWebSocketハンドラーを登録します。3章の `svr.Get()` や `svr.Post()` と同じ感覚ですね。

ハンドラーの中では、`ws.read(msg)` でメッセージを待ちます。接続が閉じられると `read()` が `false` を返すので、ループを抜けます。`ws.send(msg)` でメッセージを送り返します。

## クライアントからの接続

`httplib::ws::WebSocketClient` を使ってサーバーに接続してみましょう。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::ws::WebSocketClient client("ws://localhost:8080/ws");

    if (!client.connect()) {
        std::cout << "Connection failed" << std::endl;
        return 1;
    }

    // メッセージを送信
    client.send("Hello, WebSocket!");

    // サーバーからの応答を受信
    std::string msg;
    if (client.read(msg)) {
        std::cout << msg << std::endl;  // Hello, WebSocket!
    }

    client.close();
}
```

コンストラクタには `ws://host:port/path` 形式のURLを渡します。`connect()` で接続を開始し、`send()` と `read()` でメッセージをやり取りします。

## テキストとバイナリ

WebSocketにはテキストとバイナリの2種類のメッセージがあります。`read()` の戻り値で区別できます。

```cpp
svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    httplib::ws::ReadResult ret;
    while ((ret = ws.read(msg))) {
        if (ret == httplib::ws::Binary) {
            ws.send(msg.data(), msg.size());  // バイナリとして送信
        } else {
            ws.send(msg);  // テキストとして送信
        }
    }
});
```

- `ws.send(const std::string &)` — テキストメッセージとして送信
- `ws.send(const char *, size_t)` — バイナリメッセージとして送信

クライアント側も同じAPIです。

## リクエスト情報へのアクセス

ハンドラーの第1引数 `req` から、ハンドシェイク時のHTTPリクエスト情報を読み取れます。認証トークンの確認などに便利です。

```cpp
svr.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    auto token = req.get_header_value("Authorization");
    if (token.empty()) {
        ws.close(httplib::ws::CloseStatus::PolicyViolation, "unauthorized");
        return;
    }

    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});
```

## WSSで使う

HTTPS上のWebSocket（WSS）にも対応しています。サーバー側は `httplib::SSLServer` にWebSocketハンドラーを登録するだけです。

```cpp
httplib::SSLServer svr("cert.pem", "key.pem");

svr.WebSocket("/ws", [](const httplib::Request &, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.read(msg)) {
        ws.send(msg);
    }
});

svr.listen("0.0.0.0", 8443);
```

クライアント側は `wss://` スキームを使います。

```cpp
httplib::ws::WebSocketClient client("wss://localhost:8443/ws");
```

## 次のステップ

WebSocketの基本がわかりましたね。ここまでで Tourは終わりです。

次のページでは、Tourで取り上げなかった機能をまとめて紹介します。

**次:** [What's Next](../09-whats-next)
