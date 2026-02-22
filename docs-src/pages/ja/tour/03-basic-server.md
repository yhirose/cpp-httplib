---
title: "Basic Server"
order: 3
---

前章ではクライアントからリクエストを送りました。そのとき、`test_server.cpp` というサーバーを使いましたね。この章では、あのサーバーの仕組みをひとつずつ紐解いていきます。

## サーバーの起動

ルーティングを登録したら、最後に `svr.listen()` を呼んでサーバーを起動します。

```cpp
svr.listen("0.0.0.0", 8080);
```

第1引数はホスト、第2引数はポート番号です。`"0.0.0.0"` を指定すると、すべてのネットワークインターフェースでリクエストを受け付けます。自分のマシンからのアクセスだけに限定したいときは `"127.0.0.1"` を使います。

`listen()` はブロッキング呼び出しです。サーバーが停止するまで、この行から先には進みません。ターミナルで `Ctrl+C` を押すか、別スレッドから `svr.stop()` を呼ぶまでサーバーは動き続けます。

## ルーティング

サーバーの核になるのは「ルーティング」です。どのURLに、どのHTTPメソッドでアクセスされたら、何をするか。それを登録する仕組みです。

```cpp
httplib::Server svr;

svr.Get("/hi", [](const httplib::Request &req, httplib::Response &res) {
    res.set_content("Hello!", "text/plain");
});
```

`svr.Get()` は、GETリクエストに対するハンドラーを登録します。第1引数がパス、第2引数がハンドラー関数です。`/hi` にGETリクエストが来たら、このラムダが呼ばれます。

HTTPメソッドごとにメソッドが用意されています。

```cpp
svr.Get("/path",    handler);  // GET
svr.Post("/path",   handler);  // POST
svr.Put("/path",    handler);  // PUT
svr.Delete("/path", handler);  // DELETE
```

ハンドラーのシグネチャは `(const httplib::Request &req, httplib::Response &res)` です。`auto` を使って短く書くこともできます。

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

パスが一致したときだけハンドラーが呼ばれます。登録されていないパスにアクセスすると、自動的に404が返ります。

## リクエストオブジェクト

ハンドラーの第1引数 `req` から、クライアントが送ってきた情報を読み取れます。

### ボディ

`req.body` でリクエストボディを取得できます。型は `std::string` です。

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    // クライアントが送ったボディをそのまま返す
    res.set_content(req.body, "text/plain");
});
```

### ヘッダー

`req.get_header_value()` でリクエストヘッダーの値を取得できます。

```cpp
svr.Get("/check", [](const auto &req, auto &res) {
    auto auth = req.get_header_value("Authorization");
    res.set_content("Auth: " + auth, "text/plain");
});
```

### クエリパラメーターとフォームデータ

`req.get_param_value()` でパラメーターを取得できます。GETのクエリパラメーターと、POSTのフォームデータの両方に使えます。

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

`/search?q=cpp-httplib` にアクセスすると、`q` の値は `"cpp-httplib"` になります。

すべてのパラメーターをループで処理したいときは、`req.params` を使います。

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

### ファイルアップロード

マルチパートフォームでアップロードされたファイルは、`req.form.get_file()` で取得します。

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

`f.filename` でファイル名、`f.content` でファイルの中身にアクセスできます。

## パスパラメーター

URLの一部を変数として受け取りたいことがあります。たとえば `/users/42` の `42` を取得したい場合です。`:param` 記法を使うと、URLの一部をキャプチャできます。

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

`/users/42` にアクセスすると、`req.path_params.at("id")` は `"42"` を返します。`/users/100` なら `"100"` です。

複数のパスパラメーターも使えます。

```cpp
svr.Get("/users/:user_id/posts/:post_id", [](const auto &req, auto &res) {
    auto user_id = req.path_params.at("user_id");
    auto post_id = req.path_params.at("post_id");
    res.set_content("User: " + user_id + ", Post: " + post_id, "text/plain");
});
```

### 正規表現パターン

`:param` の代わりに正規表現をパスに書くこともできます。キャプチャグループの値は `req.matches` で取得します。型は `std::smatch` です。

```cpp
// 数字のみのIDを受け付ける
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];  // 最初のキャプチャグループ
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

`/files/42` にはマッチしますが、`/files/abc` にはマッチしません。入力値を絞り込みたいときに便利です。

## レスポンスの組み立て

ハンドラーの第2引数 `res` を使って、クライアントに返すレスポンスを組み立てます。

### ボディとContent-Type

`res.set_content()` でボディとContent-Typeを設定します。これだけでステータスコード200のレスポンスが返ります。

```cpp
svr.Get("/hi", [](const auto &req, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

### ステータスコード

ステータスコードを変えたいときは、`res.status` に代入します。

```cpp
svr.Get("/not-found", [](const auto &req, auto &res) {
    res.status = 404;
    res.set_content("Not found", "text/plain");
});
```

### レスポンスヘッダー

`res.set_header()` でレスポンスヘッダーを追加できます。

```cpp
svr.Get("/with-header", [](const auto &req, auto &res) {
    res.set_header("X-Custom", "my-value");
    res.set_content("Hello!", "text/plain");
});
```

## 前章のサーバーを読み解く

ここまでの知識を使って、前章で使った `test_server.cpp` を改めて見てみましょう。

### GET /hi

```cpp
svr.Get("/hi", [](const auto &, auto &res) {
    res.set_content("Hello!", "text/plain");
});
```

最もシンプルなハンドラーです。リクエストの情報は使わないので、`req` の変数名を省略しています。`"Hello!"` というテキストをそのまま返します。

### GET /search

```cpp
svr.Get("/search", [](const auto &req, auto &res) {
    auto q = req.get_param_value("q");
    res.set_content("Query: " + q, "text/plain");
});
```

`req.get_param_value("q")` でクエリパラメーター `q` の値を取り出します。`/search?q=cpp-httplib` なら、レスポンスは `"Query: cpp-httplib"` になります。

### POST /post

```cpp
svr.Post("/post", [](const auto &req, auto &res) {
    res.set_content(req.body, "text/plain");
});
```

クライアントが送ったリクエストボディを、そのままレスポンスとして返すエコーサーバーです。`req.body` にボディが丸ごと入っています。

### POST /submit

```cpp
svr.Post("/submit", [](const auto &req, auto &res) {
    std::string result;
    for (auto &[key, val] : req.params) {
        result += key + " = " + val + "\n";
    }
    res.set_content(result, "text/plain");
});
```

フォームデータとして送られたキーと値のペアを、`req.params` でループ処理しています。構造化束縛 `auto &[key, val]` を使って、各ペアを取り出しています。

### POST /upload

```cpp
svr.Post("/upload", [](const auto &req, auto &res) {
    auto f = req.form.get_file("file");
    auto content = f.filename + " (" + std::to_string(f.content.size()) + " bytes)";
    res.set_content(content, "text/plain");
});
```

マルチパートフォームで送られたファイルを受け取ります。`req.form.get_file("file")` で `"file"` という名前のフィールドを取得し、`f.filename` と `f.content.size()` でファイル名とサイズを返しています。

### GET /users/:id

```cpp
svr.Get("/users/:id", [](const auto &req, auto &res) {
    auto id = req.path_params.at("id");
    res.set_content("User ID: " + id, "text/plain");
});
```

`:id` の部分がパスパラメーターです。`req.path_params.at("id")` で値を取り出しています。`/users/42` なら `"42"`、`/users/alice` なら `"alice"` が得られます。

### GET /files/(\d+)

```cpp
svr.Get(R"(/files/(\d+))", [](const auto &req, auto &res) {
    auto id = req.matches[1];
    res.set_content("File ID: " + std::string(id), "text/plain");
});
```

正規表現 `(\d+)` で数字だけのIDにマッチします。`/files/42` にはマッチしますが、`/files/abc` は404になります。`req.matches[1]` で最初のキャプチャグループの値を取得しています。

## 次のステップ

サーバーの基本がわかりましたね。ルーティング、リクエストの読み取り、レスポンスの組み立て。これだけで、十分に実用的なAPIサーバーが作れます。

次は、静的ファイルの配信を見てみましょう。HTMLやCSSを配信するサーバーを作ります。

**次:** [Static File Server](../04-static-file-server)
