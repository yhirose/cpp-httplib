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

## 静的ファイルは明示的に有効にする

`set_mount_point()`や`Response::set_file_content()`でファイルをそのまま返す場合、デフォルトでは圧縮されません。有効にするには次を呼びます。

```cpp
svr.set_static_file_compression(true);
```

リクエストのたびに圧縮が走り、圧縮後のバイト列はレスポンスを書き終えるまでメモリに載ります。つまりピーク時のコストは同時処理中のリクエスト数に比例します。サイズ上限はこのためのもので、`set_static_file_compression_max_length()`を超えるファイルは圧縮されません。デフォルトは4MB、`0`で無制限、コンパイル時に決めるなら`CPPHTTPLIB_STATIC_FILE_COMPRESSION_MAX_LENGTH`です。

```cpp
svr.set_static_file_compression_max_length(1024 * 1024);
```

圧縮しても`Content-Length`は付いたままなので、`HEAD`は`GET`と同じサイズを返します。細かい挙動として、Rangeリクエストは非圧縮の表現から切り出して返し、`ETag`には`W/"...-gzip"`のように使われた圧縮方式が入ります。

なお`set_content_provider()`で登録したコンテンツプロバイダは対象外です。圧縮器を通すと、内部バッファが埋まるまで書き込みが送出されず、ボディを少しずつ生成するプロバイダが止まってしまうためです。生成したボディを圧縮したい場合は`set_chunked_content_provider()`を使ってください。

> **Note:** 最小サイズのしきい値はありません。圧縮対象のMIMEタイプでクライアントが受け入れていれば、ボディの大きさによらず圧縮されます。数バイトのレスポンスはgzipのヘッダ分だけかえって大きくなるので、小さいレスポンスを避けたい場合はハンドラ側で判断してください。

> クライアント側の挙動は[C15. 圧縮を有効にする](../c15-compression)を参照してください。
