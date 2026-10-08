---
title: "C15. 圧縮を有効にする"
order: 15
status: "draft"
---

cpp-httplibは送信時の圧縮と受信時の解凍をサポートしています。ただし、zlibまたはBrotliを有効にしてビルドしておく必要があります。

## ビルド時の準備

圧縮機能を使うには、`httplib.h`をインクルードする前に次のマクロを定義しておきます。

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT    // gzip / deflate
#define CPPHTTPLIB_BROTLI_SUPPORT  // brotli
#include <httplib.h>
```

リンク時に`zlib`や`brotli`のライブラリも必要です。

## リクエストボディを圧縮して送る

```cpp
httplib::Client cli("https://api.example.com");
cli.set_compress(true);

std::string big_payload = build_payload();
auto res = cli.Post("/api/data", big_payload, "application/json");
```

`set_compress(true)`を呼んでおくと、POSTやPUTのリクエストボディが圧縮されて送信されます。圧縮方式は、ビルドで有効にしたもののうち、Brotli、gzip、Zstdの順で最初に当てはまるものです。サーバー側もその方式に対応している必要があります。

## レスポンスを解凍する

```cpp
httplib::Client cli("https://api.example.com");
cli.set_decompress(true); // デフォルトで有効

auto res = cli.Get("/api/data");
std::cout << res->body << std::endl;
```

`set_decompress(true)`を呼ぶと、サーバーが`Content-Encoding: gzip`などで圧縮したレスポンスを自動で解凍してくれます。`res->body`には解凍済みのデータが入ります。

デフォルトで有効なので、通常は何もしなくても解凍されます。あえて生の圧縮データを触りたいときだけ`set_decompress(false)`にしましょう。

> **Warning:** 圧縮ライブラリを1つも有効にしていないビルドでは、`set_compress(true)`を呼んでもリクエストは圧縮されません。また、ビルドで有効にしていない方式で圧縮されたレスポンスが返ってくると、リクエストは`Error::UnsupportedContentEncoding`で失敗します。うまく動かないときは、まずマクロの定義を確認しましょう。
