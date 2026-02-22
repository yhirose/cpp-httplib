---
title: "What's Next"
order: 9
---

Tourお疲れさまでした！ cpp-httplibの基本はひと通り押さえましたね。でも、まだまだ便利な機能があります。Tourで取り上げなかった機能をカテゴリー別に紹介します。

## Streaming API

LLMのストリーミング応答や大きなファイルのダウンロードでは、レスポンス全体をメモリに載せたくないですよね。`stream::Get()` を使えば、データをチャンクごとに処理できます。

```cpp
httplib::Client cli("http://localhost:11434");

auto result = httplib::stream::Get(cli, "/api/generate");

if (result) {
    while (result.next()) {
        std::cout.write(result.data(), result.size());
    }
}
```

`Get()` に `content_receiver` コールバックを渡す方法もあります。こちらはKeep-Aliveと併用できます。

```cpp
httplib::Client cli("http://localhost:8080");

cli.Get("/stream", [](const char *data, size_t len) {
    std::cout.write(data, len);
    return true;
});
```

サーバー側には `set_content_provider()` と `set_chunked_content_provider()` があります。サイズがわかっているなら前者、不明なら後者を使ってください。

```cpp
// サイズ指定あり（Content-Length が設定される）
svr.Get("/file", [](const auto &, auto &res) {
    auto size = get_file_size("large.bin");
    res.set_content_provider(size, "application/octet-stream",
        [](size_t offset, size_t length, httplib::DataSink &sink) {
            // offset から length バイト分を送る
            return true;
        });
});

// サイズ不明（Chunked Transfer Encoding）
svr.Get("/stream", [](const auto &, auto &res) {
    res.set_chunked_content_provider("text/plain",
        [](size_t offset, httplib::DataSink &sink) {
            sink.write("chunk\n", 6);
            return true;  // falseを返すと終了
        });
});
```

大きなファイルのアップロードには `make_file_provider()` が便利です。ファイルを全部メモリに読み込まず、ストリーミングで送れます。

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/upload", {}, {
    httplib::make_file_provider("file", "/path/to/large-file.zip")
});
```

## Server-Sent Events (SSE)

SSEクライアントも用意しています。自動再接続や `Last-Event-ID` による再開にも対応しています。

```cpp
httplib::Client cli("http://localhost:8080");
httplib::sse::SSEClient sse(cli, "/events");

sse.on_message([](const httplib::sse::SSEMessage &msg) {
    std::cout << msg.event << ": " << msg.data << std::endl;
});

sse.start();  // ブロッキング、自動再接続あり
```

イベントタイプごとにハンドラーを分けることもできますよ。

```cpp
sse.on_event("update", [](const httplib::sse::SSEMessage &msg) {
    // "update" イベントだけ処理
});
```

## 認証

クライアントにはBasic認証、Bearer Token認証、Digest認証のヘルパーを用意しています。

```cpp
httplib::Client cli("https://api.example.com");
cli.set_basic_auth("user", "password");
cli.set_bearer_token_auth("my-token");
```

## 圧縮

gzip、Brotli、Zstandardによる圧縮・展開に対応しています。使いたい方式のマクロを定義してコンパイルしましょう。

| 圧縮方式 | マクロ定義 |
| -- | -- |
| gzip | `CPPHTTPLIB_ZLIB_SUPPORT` |
| Brotli | `CPPHTTPLIB_BROTLI_SUPPORT` |
| Zstandard | `CPPHTTPLIB_ZSTD_SUPPORT` |

```cpp
httplib::Client cli("https://example.com");
cli.set_compress(true);    // リクエストボディを圧縮
cli.set_decompress(true);  // レスポンスボディを展開
```

## プロキシ

HTTPプロキシ経由で接続できます。

```cpp
httplib::Client cli("https://example.com");
cli.set_proxy("proxy.example.com", 8080);
cli.set_proxy_basic_auth("user", "password");
```

## タイムアウト

接続・読み取り・書き込みのタイムアウトを個別に設定できます。

```cpp
httplib::Client cli("https://example.com");
cli.set_connection_timeout(5, 0);  // 5秒
cli.set_read_timeout(10, 0);       // 10秒
cli.set_write_timeout(10, 0);      // 10秒
```

## Keep-Alive

同じサーバーに何度もリクエストするなら、Keep-Aliveを有効にしましょう。TCP接続を再利用するので効率的です。

```cpp
httplib::Client cli("https://example.com");
cli.set_keep_alive(true);
```

## サーバーのミドルウェア

リクエスト処理の前後にフックを挟めます。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    // すべてのリクエストの前に実行される
    return httplib::Server::HandlerResponse::Unhandled;  // 通常のルーティングに進む
});

svr.set_post_routing_handler([](const auto &req, auto &res) {
    // レスポンスが返された後に実行される
    res.set_header("X-Server", "cpp-httplib");
});
```

`req.user_data` を使うと、ミドルウェアからハンドラーにデータを渡せます。認証トークンのデコード結果を共有するときに便利です。

```cpp
svr.set_pre_routing_handler([](const auto &req, auto &res) {
    req.user_data["auth_user"] = std::string("alice");
    return httplib::Server::HandlerResponse::Unhandled;
});

svr.Get("/me", [](const auto &req, auto &res) {
    auto user = std::any_cast<std::string>(req.user_data.at("auth_user"));
    res.set_content("Hello, " + user, "text/plain");
});
```

エラーや例外のハンドラーもカスタマイズできますよ。

```cpp
svr.set_error_handler([](const auto &req, auto &res) {
    res.set_content("Custom Error Page", "text/html");
});

svr.set_exception_handler([](const auto &req, auto &res, std::exception_ptr ep) {
    res.status = 500;
    res.set_content("Internal Server Error", "text/plain");
});
```

## ロギング

サーバーでもクライアントでもロガーを設定できます。

```cpp
svr.set_logger([](const auto &req, const auto &res) {
    std::cout << req.method << " " << req.path << " " << res.status << std::endl;
});
```

## Unix Domain Socket

TCP以外に、Unix Domain Socketでの通信にも対応しています。同じマシン上のプロセス間通信に使えます。

```cpp
// サーバー
httplib::Server svr;
svr.set_address_family(AF_UNIX);
svr.listen("/tmp/httplib.sock", 0);
```

```cpp
// クライアント
httplib::Client cli("http://localhost");
cli.set_address_family(AF_UNIX);
cli.set_hostname_addr_map({{"localhost", "/tmp/httplib.sock"}});

auto res = cli.Get("/");
```

## さらに詳しく

もっと詳しく知りたいときは、以下を参照してください。

- Cookbook — よくあるユースケースのレシピ集
- [README](https://github.com/yhirose/cpp-httplib/blob/master/README.md) — 全APIのリファレンス
- [README-sse](https://github.com/yhirose/cpp-httplib/blob/master/README-sse.md) — Server-Sent Eventsの使い方
- [README-stream](https://github.com/yhirose/cpp-httplib/blob/master/README-stream.md) — Streaming APIの使い方
- [README-websocket](https://github.com/yhirose/cpp-httplib/blob/master/README-websocket.md) — WebSocketサーバーの使い方
