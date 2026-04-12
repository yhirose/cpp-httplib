---
title: "S05. 大きなファイルをストリーミングで返す"
order: 24
status: "draft"
---

巨大なファイルやリアルタイムに生成されるデータをレスポンスとして返したいとき、全体をメモリに載せるのは現実的ではありません。`Response::set_content_provider()`を使うと、データをチャンクごとに生成しながら送れます。

## サイズがわかっている場合

```cpp
svr.Get("/download", [](const httplib::Request &req, httplib::Response &res) {
  size_t total_size = get_file_size("large.bin");

  res.set_content_provider(
    total_size, "application/octet-stream",
    [](size_t offset, size_t length, httplib::DataSink &sink) {
      auto data = read_range_from_file("large.bin", offset, length);
      sink.write(data.data(), data.size());
      return true;
    });
});
```

ラムダが呼ばれるたびに`offset`と`length`が渡されるので、その範囲だけ読み込んで`sink.write()`で送ります。メモリには常に少量のチャンクしか載りません。

## ファイルをそのまま返す

ただファイルを返すだけなら、`set_file_content()`のほうがずっと簡単です。

```cpp
svr.Get("/download", [](const httplib::Request &req, httplib::Response &res) {
  res.set_file_content("large.bin", "application/octet-stream");
});
```

内部でストリーミング送信をしてくれるので、大きなファイルでも安心です。Content-Typeを省略すれば、拡張子から自動で判定されます。

## サイズが不明な場合はチャンク転送

リアルタイムに生成されるデータなど、サイズが事前にわからないときは`set_chunked_content_provider()`を使います。HTTP chunked transfer-encodingとして送信されます。

```cpp
svr.Get("/events", [](const httplib::Request &req, httplib::Response &res) {
  res.set_chunked_content_provider(
    "text/plain",
    [](size_t offset, httplib::DataSink &sink) {
      auto chunk = produce_next_chunk();
      if (chunk.empty()) {
        sink.done(); // 送信終了
        return true;
      }
      sink.write(chunk.data(), chunk.size());
      return true;
    });
});
```

データがもう無くなったら`sink.done()`を呼んで終了します。

> **Note:** プロバイダラムダは複数回呼ばれます。キャプチャする変数のライフタイムに気をつけてください。必要なら`std::shared_ptr`などで包みましょう。

> ファイルダウンロードとして扱いたい場合は[S06. ファイルダウンロードレスポンスを返す](s06-download-response)を参照してください。
