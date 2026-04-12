---
title: "S08. レスポンスを圧縮して返す"
order: 27
status: "draft"
---

cpp-httplibは、クライアントが`Accept-Encoding`で対応を表明していれば、レスポンスボディを自動で圧縮してくれます。ハンドラ側で特別なことをする必要はありません。対応しているのはgzip、Brotli、Zstdです。

## ビルド時の準備

圧縮機能を使うには、`httplib.h`をインクルードする前に対応するマクロを定義しておきます。

```cpp
#define CPPHTTPLIB_ZLIB_SUPPORT     // gzip
#define CPPHTTPLIB_BROTLI_SUPPORT   // brotli
#define CPPHTTPLIB_ZSTD_SUPPORT     // zstd
#include <httplib.h>
```

それぞれ`zlib`、`brotli`、`zstd`をリンクする必要があります。必要な圧縮方式だけ有効にすればOKです。

## 使い方

```cpp
svr.Get("/api/data", [](const httplib::Request &req, httplib::Response &res) {
  std::string body = build_large_response();
  res.set_content(body, "application/json");
});
```

これだけです。クライアントが`Accept-Encoding: gzip`を送ってきていれば、cpp-httplibが自動でgzip圧縮して返します。レスポンスには`Content-Encoding: gzip`と`Vary: Accept-Encoding`が自動で付きます。

## 圧縮の優先順位

クライアントが複数の方式を受け入れる場合、Brotli → Zstd → gzipの順に選ばれます（ビルドで有効になっている中から）。クライアント側では気にせず、一番効率の良い方式で圧縮されます。

## ストリーミングレスポンスも圧縮される

`set_chunked_content_provider()`で返すストリーミングレスポンスも、同じように自動で圧縮されます。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      // ...
    });
});
```

> **Note:** 小さなレスポンスは圧縮しても効果が薄く、むしろCPU時間を無駄にすることがあります。cpp-httplibは小さすぎるボディは圧縮をスキップします。

> クライアント側の挙動は[C15. 圧縮を有効にする](c15-compression)を参照してください。
