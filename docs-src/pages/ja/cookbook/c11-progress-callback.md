---
title: "C11. 進捗コールバックを使う"
order: 11
status: "draft"
---

ダウンロードやアップロードの進捗を表示したいときは、`DownloadProgress`または`UploadProgress`コールバックを渡します。どちらも`(current, total)`の2引数を取る関数オブジェクトです。

## ダウンロードの進捗

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Get("/large-file",
  [](size_t current, size_t total) {
    auto percent = (total > 0) ? (current * 100 / total) : 0;
    std::cout << "\rDownloading: " << percent << "% ("
              << current << "/" << total << ")" << std::flush;
    return true; // falseを返すとダウンロードを中止
  });
std::cout << std::endl;
```

コールバックはデータを受信するたびに呼ばれます。`total`はContent-Lengthの値です。chunked転送のようにContent-Lengthのないレスポンスでは、進捗コールバックは一度も呼ばれません。

## アップロードの進捗

アップロード側も同じ形です。`Post()`や`Put()`の最後の引数に`UploadProgress`を渡します。

```cpp
httplib::Client cli("http://localhost:8080");

std::string body = load_large_body();

auto res = cli.Post("/upload", body, "application/octet-stream",
  [](size_t current, size_t total) {
    auto percent = current * 100 / total;
    std::cout << "\rUploading: " << percent << "%" << std::flush;
    return true;
  });
std::cout << std::endl;
```

## 中断する

コールバックから`false`を返すと、転送を中止できます。UI側で「キャンセル」ボタンが押されたら`false`を返す、といった使い方ができます。

```cpp
std::atomic<bool> cancelled{false};

auto res = cli.Get("/large-file",
  [&](size_t current, size_t total) {
    return !cancelled.load();
  });
```

> **Note:** Content-Lengthのないレスポンスでは進捗コールバックが呼ばれないため、この方法は使えません。代わりに`ContentReceiver`から`false`を返して中断します。

> **Note:** `ContentReceiver`と進捗コールバックは同時に使えます。ファイルに書き出しながら進捗を表示したいときは、両方を渡しましょう。

> ファイル保存と組み合わせる具体例は[C01. レスポンスボディを取得する / ファイルに保存する](../c01-get-response-body)も参照してください。
