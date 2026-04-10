---
title: "C07. ファイルをマルチパートフォームとしてアップロードする"
order: 7
status: "draft"
---

HTMLフォームの`<input type="file">`と同じ形式でファイルを送りたいときは、マルチパートフォーム（`multipart/form-data`）を使います。cpp-httplibは`UploadFormDataItems`と`FormDataProviderItems`の2種類のAPIを用意しています。使い分けの基準は**ファイルサイズ**です。

## 小さなファイルを送る

ファイル内容をメモリに読み込んでから送る方法です。サイズが小さいなら、これが一番シンプルです。

```cpp
httplib::Client cli("http://localhost:8080");

std::ifstream ifs("avatar.png", std::ios::binary);
std::string content((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());

httplib::UploadFormDataItems items = {
  {"name", "Alice", "", ""},
  {"avatar", content, "avatar.png", "image/png"},
};

auto res = cli.Post("/upload", items);
```

`UploadFormData`の各要素は`{name, content, filename, content_type}`の4つです。テキストフィールドなら`filename`と`content_type`を空文字にしておきます。

## 大きなファイルをストリーミングで送る

ファイル全体をメモリに載せずに、チャンクごとに送りたいときは`make_file_provider()`を使います。内部でファイルを少しずつ読みながら送信するので、巨大なファイルでもメモリを圧迫しません。

```cpp
httplib::Client cli("http://localhost:8080");

httplib::UploadFormDataItems items = {
  {"name", "Alice", "", ""},
};

httplib::FormDataProviderItems provider_items = {
  httplib::make_file_provider("video", "large-video.mp4", "", "video/mp4"),
};

auto res = cli.Post("/upload", httplib::Headers{}, items, provider_items);
```

`make_file_provider()`の引数は`(フォーム名, ファイルパス, ファイル名, Content-Type)`です。ファイル名を空にするとファイルパスがそのまま使われます。

> **Note:** `UploadFormDataItems`と`FormDataProviderItems`は同じリクエスト内で併用できます。テキストフィールドは`UploadFormDataItems`、ファイルは`FormDataProviderItems`、という使い分けがきれいです。

> アップロードの進捗を表示したい場合はC11. 進捗コールバックを使うを参照してください。
