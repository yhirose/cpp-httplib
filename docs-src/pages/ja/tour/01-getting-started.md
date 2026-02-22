---
title: "Getting Started"
order: 1
---

cpp-httplibを始めるのに必要なのは、`httplib.h`とC++コンパイラーだけです。ファイルをダウンロードして、Hello Worldサーバーを動かすところまでやってみましょう。

## httplib.h の入手

GitHubから直接ダウンロードできます。常に最新版を使ってください。

```sh
curl -LO https://github.com/yhirose/cpp-httplib/raw/refs/tags/latest/httplib.h
```

ダウンロードした `httplib.h` をプロジェクトのディレクトリに置けば、準備完了です。

## コンパイラーの準備

| OS | 開発環境 | セットアップ |
| -- | -------- | ------------ |
| macOS | Apple Clang | Xcode Command Line Tools (`xcode-select --install`) |
| Ubuntu | clang++ または g++ | `apt install clang` または `apt install g++` |
| Windows | MSVC | Visual Studio 2022 以降（C++ コンポーネントを含めてインストール） |

## Hello World サーバー

次のコードを `server.cpp` として保存しましょう。

```cpp
#include "httplib.h"

int main() {
    httplib::Server svr;

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello, World!", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);
}
```

たった数行で、HTTPリクエストに応答するサーバーが書けます。

## コンパイルと実行

このチュートリアルのサンプルコードは、コードを簡潔に書けるC++17で書いています。cpp-httplib自体はC++11でもコンパイルできます。

```sh
# macOS
clang++ -std=c++17 -o server server.cpp

# Linux
# `-pthread`: cpp-httplibは内部でスレッドを使用
clang++ -std=c++17 -pthread -o server server.cpp

# Windows (Developer Command Prompt)
# `/EHsc`: C++例外処理を有効化
cl /EHsc /std:c++17 server.cpp
```

コンパイルできたら実行します。

```sh
# macOS / Linux
./server

# Windows
server.exe
```

ブラウザで `http://localhost:8080` を開いてください。"Hello, World!" と表示されれば成功です。

`curl` でも確認できます。

```sh
curl http://localhost:8080/
# Hello, World!
```

サーバーを停止するには、ターミナルで `Ctrl+C` を押します。

## 次のステップ

サーバーの基本がわかりましたね。次は、クライアント側を見てみましょう。cpp-httplibはHTTPクライアント機能も備えています。

**次:** [Basic Client](../02-basic-client)
