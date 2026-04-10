---
title: "C09. チャンク転送でボディを送る"
order: 9
status: "draft"
---

送信するボディのサイズが事前にわからないとき、たとえばリアルタイムに生成されるデータや別のストリームから流し込むデータを送りたいときは、`ContentProviderWithoutLength`を使います。HTTPのチャンク転送エンコーディング（chunked transfer-encoding）として送信されます。

## 基本の使い方

```cpp
httplib::Client cli("http://localhost:8080");

auto res = cli.Post("/stream",
  [&](size_t offset, httplib::DataSink &sink) {
    std::string chunk = produce_next_chunk();
    if (chunk.empty()) {
      sink.done(); // 送信終了
      return true;
    }
    return sink.write(chunk.data(), chunk.size());
  },
  "application/octet-stream");
```

ラムダは「次のチャンクを作って`sink.write()`で送る」だけです。データがもう無くなったら`sink.done()`を呼べば送信が完了します。

## サイズがわかっている場合

送信するボディの**合計サイズが事前にわかっている**ときは、`ContentProvider`（`size_t offset, size_t length, DataSink &sink`を取るタイプ）と合計サイズを渡す別のオーバーロードを使います。

```cpp
size_t total_size = get_total_size();

auto res = cli.Post("/upload", total_size,
  [&](size_t offset, size_t length, httplib::DataSink &sink) {
    auto data = read_range(offset, length);
    return sink.write(data.data(), data.size());
  },
  "application/octet-stream");
```

サイズがわかっているとContent-Lengthヘッダーが付くので、サーバー側で進捗を把握しやすくなります。可能ならこちらを使いましょう。

> **Detail:** `sink.write()`は書き込みが成功したかどうかを`bool`で返します。`false`が返ったら回線が切れています。ラムダはそのまま`false`を返して終了しましょう。

> ファイルをそのまま送るだけなら、`make_file_body()`が便利です。C08. ファイルを生バイナリとしてPOSTするを参照してください。
