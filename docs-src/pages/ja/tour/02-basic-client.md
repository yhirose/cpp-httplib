---
title: "Basic Client"
order: 2
---

cpp-httplibはサーバーだけでなく、HTTPクライアント機能も備えています。`httplib::Client` を使って、GETやPOSTリクエストを送ってみましょう。

## テスト用サーバーの準備

クライアントの動作を確認するために、リクエストを受け付けるサーバーを用意します。次のコードを `test_server.cpp` として保存し、前章と同じ手順でコンパイル・実行してください。サーバーの詳しい解説は次章で行います。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.Get("/hi", [](const auto &, auto &res) {
        res.set_content("Hello!", "text/plain");
    });

    svr.Get("/search", [](const auto &req, auto &res) {
        auto q = req.get_param_value("q");
        res.set_content("Query: " + q, "text/plain");
    });

    svr.Post("/post", [](const auto &req, auto &res) {
        res.set_content(req.body, "text/plain");
    });

    svr.Post("/submit", [](const auto &req, auto &res) {
        std::string result;
        for (auto &[key, val] : req.params) {
            result += key + " = " + val + "\n";
        }
        res.set_content(result, "text/plain");
    });

    svr.Post("/upload", [](const auto &req, auto &res) {
        auto f = req.form.get_file("file");
        auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
        res.set_content(content, "text/plain");
    });

    svr.Get("/users/:id", [](const auto &req, auto &res) {
        auto id = req.path_params.at("id");
        res.set_content("User ID: " + id, "text/plain");
    });

    svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
        auto id = req.matches[1];
        res.set_content("File ID: " + std::string(id), "text/plain");
    });

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

## GETリクエスト

サーバーが起動したら、別のターミナルを開いて試してみましょう。まず、最もシンプルなGETリクエストです。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Client cli("http://localhost:8080");

    auto res = cli.Get("/hi");
    if (res) {
        std::cout << res->status << std::endl;  // 200
        std::cout << res->body << std::endl;    // Hello!
    }
}
```

`httplib::Client` のコンストラクターにサーバーのアドレスを渡し、`Get()` でリクエストを送ります。戻り値の `res` からステータスコードやボディを取得できます。

対応する `curl` コマンドはこうなります。

```sh
curl http://localhost:8080/hi
# Hello!
```

## レスポンスの確認

レスポンスには、ステータスコードとボディ以外にもヘッダー情報が含まれています。

```cpp
auto res = cli.Get("/hi");
if (res) {
    // ステータスコード
    std::cout << res->status << std::endl;  // 200

    // ボディ
    std::cout << res->body << std::endl;  // Hello!

    // ヘッダー
    std::cout << res->get_header_value("Content-Type") << std::endl;  // text/plain
}
```

`res->body` は `std::string` なので、JSON レスポンスをパースしたい場合は [nlohmann/json](https://github.com/nlohmann/json) などの JSON ライブラリにそのまま渡せます。

## クエリパラメーター

GETリクエストにクエリパラメーターを付けるには、URLに直接書くか、`httplib::Params` を使います。

```cpp
auto res = cli.Get("/search", httplib::Params{{"q", "cpp-httplib"}});
if (res) {
    std::cout << res->body << std::endl;  // Query: cpp-httplib
}
```

`httplib::Params` を使うと、特殊文字のURLエンコードを自動で行ってくれます。

```sh
curl "http://localhost:8080/search?q=cpp-httplib"
# Query: cpp-httplib
```

## パスパラメーター

URLのパスに値を直接埋め込む場合も、クライアント側は特別なAPIは不要です。パスをそのまま `Get()` に渡すだけです。

```cpp
auto res = cli.Get("/users/42");
if (res) {
    std::cout << res->body << std::endl;  // User ID: 42
}
```

```sh
curl http://localhost:8080/users/42
# User ID: 42
```

テスト用サーバーには、正規表現でIDを数字のみに絞った `/files/(\d+)` もあります。

```cpp
auto res = cli.Get("/files/42");
if (res) {
    std::cout << res->body << std::endl;  // File ID: 42
}
```

```sh
curl http://localhost:8080/files/42
# File ID: 42
```

`/files/abc` のように数字以外を渡すと404が返ります。仕組みは次章で解説します。

## リクエストヘッダー

カスタムHTTPヘッダーを付けるには、`httplib::Headers` を渡します。`Get()` や `Post()` のどちらでも使えます。

```cpp
auto res = cli.Get("/hi", httplib::Headers{
    {"Authorization", "Bearer my-token"}
});
```

```sh
curl -H "Authorization: Bearer my-token" http://localhost:8080/hi
```

## POSTリクエスト

テキストデータをPOSTしてみましょう。`Post()` の第2引数にボディ、第3引数にContent-Typeを指定します。

```cpp
auto res = cli.Post("/post", "Hello, Server!", "text/plain");
if (res) {
    std::cout << res->status << std::endl;  // 200
    std::cout << res->body << std::endl;    // Hello, Server!
}
```

テスト用サーバーの `/post` はボディをそのまま返すので、送った文字列がそのまま返ってきます。

```sh
curl -X POST -H "Content-Type: text/plain" -d "Hello, Server!" http://localhost:8080/post
# Hello, Server!
```

## フォームデータの送信

HTMLフォームのように、キーと値のペアを送ることもできます。`httplib::Params` を使います。

```cpp
auto res = cli.Post("/submit", httplib::Params{
    {"name", "Alice"},
    {"age", "30"}
});
if (res) {
    std::cout << res->body << std::endl;
    // age = 30
    // name = Alice
}
```

これは `application/x-www-form-urlencoded` 形式で送信されます。

```sh
curl -X POST -d "name=Alice&age=30" http://localhost:8080/submit
```

## ファイルのPOST

ファイルをアップロードするには、`httplib::UploadFormDataItems` を使ってマルチパートフォームデータとして送信します。

```cpp
auto res = cli.Post("/upload", httplib::UploadFormDataItems{
    {"file", "Hello, File!", "hello.txt", "text/plain"}
});
if (res) {
    std::cout << res->body << std::endl;  // hello.txt (12 bytes)
}
```

`UploadFormDataItems` の各要素は `{name, content, filename, content_type}` の4つのフィールドで構成されます。

```sh
curl -F "file=Hello, File!;filename=hello.txt;type=text/plain" http://localhost:8080/upload
```

## エラーハンドリング

ネットワーク通信では、サーバーに接続できない場合があります。`res` が有効かどうかを必ず確認しましょう。

```cpp
httplib::Client cli("http://localhost:9999");  // 存在しないポート
auto res = cli.Get("/hi");

if (!res) {
    // 接続エラー
    std::cout << "Error: " << httplib::to_string(res.error()) << std::endl;
    // Error: Connection
    return 1;
}

// ここに到達すればレスポンスを受信できている
if (res->status != 200) {
    std::cout << "HTTP Error: " << res->status << std::endl;
    return 1;
}

std::cout << res->body << std::endl;
```

エラーには2つのレベルがあります。

- **接続エラー**: サーバーに到達できなかった場合。`res` が偽になり、`res.error()` でエラーの種類を取得できます
- **HTTPエラー**: サーバーからエラーステータス（404、500など）が返ってきた場合。`res` は真ですが、`res->status` を確認する必要があります

## 次のステップ

クライアントからリクエストを送る方法がわかりました。次は、サーバー側をもっと詳しく見てみましょう。ルーティングやパスパラメータなど、サーバーの機能を掘り下げます。

**次:** [Basic Server](../03-basic-server)
