---
title: "W01. WebSocketエコーサーバー／クライアントを実装する"
order: 51
status: "draft"
---

WebSocketは、クライアントとサーバーの間で**双方向**にメッセージをやり取りするためのプロトコルです。cpp-httplibはサーバーとクライアントの両方のAPIを提供しています。まずは一番シンプルなエコーサーバーから見てみましょう。

## サーバー: エコーサーバー

```cpp
#include <httplib.h>

int main() {
  httplib::Server svr;

  svr.WebSocket("/echo", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    std::string msg;
    while (ws.is_open()) {
      auto result = ws.read(msg);
      if (result == httplib::ws::ReadResult::Fail) {
        break;
      }
      ws.send(msg); // 受け取った内容をそのまま返す
    }
  });

  svr.listen("0.0.0.0", 8080);
}
```

`svr.WebSocket()`でWebSocket用のハンドラを登録します。ハンドラが呼ばれた時点で、すでにWebSocketのハンドシェイクは完了しています。ループの中で`ws.read()`して`ws.send()`するだけで、エコー動作が完成します。

`read()`の返り値は`ReadResult`列挙値で、次の3種類です。

- `ReadResult::Text`: テキストメッセージを受信
- `ReadResult::Binary`: バイナリメッセージを受信
- `ReadResult::Fail`: エラー、または接続が閉じた

## クライアント: エコーを叩く

```cpp
#include <httplib.h>

int main() {
  httplib::ws::WebSocketClient cli("ws://localhost:8080/echo");
  if (!cli.connect()) {
    std::cerr << "failed to connect" << std::endl;
    return 1;
  }

  cli.send("Hello, WebSocket!");

  std::string msg;
  if (cli.read(msg) != httplib::ws::ReadResult::Fail) {
    std::cout << "received: " << msg << std::endl;
  }

  cli.close();
}
```

URLには`ws://`（平文）または`wss://`（TLS）を指定します。`connect()`でハンドシェイクを行い、あとは`send()`と`read()`でサーバーと同じAPIでやり取りできます。

## テキストとバイナリの送り分け

`send()`には2つのオーバーロードがあり、テキストとバイナリで使い分けられます。

```cpp
ws.send("Hello");                        // テキストフレーム
ws.send(binary_data, binary_data_size);  // バイナリフレーム
```

`std::string`を受け取るオーバーロードはテキスト、`const char*`とサイズを受け取るオーバーロードはバイナリとして送られます。詳しくはW04. バイナリフレームを送受信するを参照してください。

## スレッドとの関係

WebSocket接続はハンドラが終わるまで生き続けるので、1接続につきワーカースレッドを1つ占有します。同時接続数が多い場合は、スレッドプールを動的スケーリングに設定しましょう。

```cpp
svr.new_task_queue = [] {
  return new httplib::ThreadPool(8, 128);
};
```

詳細はS21. マルチスレッド数を設定するを参照してください。

> **Note:** HTTPSサーバーの上でWebSocketを動かしたいときは、`httplib::Server`の代わりに`httplib::SSLServer`を使えば、同じ`WebSocket()`ハンドラがそのまま動きます。クライアント側は`wss://`スキームを指定するだけです。
