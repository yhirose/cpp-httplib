---
title: "Static File Server"
order: 4
---

cpp-httplibは、HTMLやCSS、画像ファイルなどの静的ファイルも配信できます。面倒な設定は要りません。`set_mount_point()` を1行呼ぶだけです。

## set_mount_point の基本

さっそくやってみましょう。`set_mount_point()` は、URLのパスとローカルディレクトリを紐づけます。

```cpp
#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server svr;

    svr.set_mount_point("/", "./html");

    std::cout << "Listening on port 8080..." << std::endl;
    svr.listen("0.0.0.0", 8080);
}
```

第1引数がURLのマウントポイント、第2引数がローカルのディレクトリパスです。この例だと、`/` へのリクエストを `./html` ディレクトリから配信します。

試してみましょう。まず `html` ディレクトリを作って、`index.html` を置きます。

```sh
mkdir html
```

```html
<!DOCTYPE html>
<html>
<head><title>My Page</title></head>
<body>
    <h1>Hello from cpp-httplib!</h1>
    <p>This is a static file.</p>
</body>
</html>
```

コンパイルして起動します。

```sh
g++ -std=c++17 -o server server.cpp -pthread
./server
```

ブラウザで `http://localhost:8080` を開いてみてください。`html/index.html` の内容が表示されるはずです。`http://localhost:8080/index.html` でも同じページが返ります。

もちろん、前章のクライアントコードや `curl` でもアクセスできますよ。

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/");
if (res) {
    std::cout << res->body << std::endl;  // HTMLが表示される
}
```

```sh
curl http://localhost:8080
```

## 複数のマウントポイント

`set_mount_point()` は何回でも呼べます。URLのパスごとに、別々のディレクトリを割り当てられます。

```cpp
svr.set_mount_point("/", "./public");
svr.set_mount_point("/assets", "./static/assets");
svr.set_mount_point("/docs", "./documentation");
```

`/assets/style.css` なら `./static/assets/style.css` を、`/docs/guide.html` なら `./documentation/guide.html` を配信します。

## ハンドラーとの組み合わせ

静的ファイルの配信と、前章で学んだルーティングハンドラーは共存できます。

```cpp
httplib::Server svr;

// APIエンドポイント
svr.Get("/api/hello", [](const auto &, auto &res) {
    res.set_content(R"({"message":"Hello!"})", "application/json");
});

// 静的ファイル配信
svr.set_mount_point("/", "./public");

svr.listen("0.0.0.0", 8080);
```

ハンドラーが先に評価されます。`/api/hello` にはハンドラーが応答し、それ以外のパスは `./public` ディレクトリからファイルを探します。

## レスポンスヘッダーの追加

`set_mount_point()` の第3引数にヘッダーを渡すと、静的ファイルのレスポンスにカスタムヘッダーを付けられます。キャッシュ制御に便利です。

```cpp
svr.set_mount_point("/", "./public", {
    {"Cache-Control", "max-age=3600"}
});
```

こうすると、ブラウザは配信されたファイルを1時間キャッシュします。

## 静的ファイルサーバー用のDockerファイル

cpp-httplibのリポジトリには、静的ファイルサーバー用の `Dockerfile` が含まれています。Docker Hubにビルド済みイメージも公開しているので、1コマンドで起動できます。

```sh
> docker run -p 8080:80 -v ./my-site:/html yhirose4dockerhub/cpp-httplib-server
Serving HTTP on 0.0.0.0:80
Mount point: / -> ./html
Press Ctrl+C to shutdown gracefully...
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 256 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:00 +0000] "GET /style.css HTTP/1.1" 200 1024 "-" "Mozilla/5.0 ..."
192.168.65.1 - - [22/Feb/2026:12:00:01 +0000] "GET /favicon.ico HTTP/1.1" 404 152 "-" "Mozilla/5.0 ..."
```

`./my-site` ディレクトリの中身が、そのままポート8080で配信されます。NGINXと同じログ形式で、アクセスの様子を確認できますよ。

## 次のステップ

静的ファイルの配信ができるようになりましたね。HTMLやCSS、JavaScriptを配信するWebサーバーが、これだけのコードで作れます。

次は、HTTPSで暗号化通信をしてみましょう。まずはTLSライブラリのセットアップからです。

**次:** [TLS Setup](../05-tls-setup)
