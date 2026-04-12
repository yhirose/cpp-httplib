---
title: "C08. ファイルを生バイナリとしてPOSTする"
order: 8
status: "draft"
---

マルチパートではなく、ファイルの中身をそのままリクエストボディとして送りたいときがあります。S3互換APIへのアップロードや、生の画像データを受け付けるエンドポイントなどです。このときは`make_file_body()`を使いましょう。

## 基本の使い方

```cpp
httplib::Client cli("https://storage.example.com");

auto [size, provider] = httplib::make_file_body("backup.tar.gz");
if (size == 0) {
  std::cerr << "Failed to open file" << std::endl;
  return 1;
}

auto res = cli.Put("/bucket/backup.tar.gz", size,
                   provider, "application/gzip");
```

`make_file_body()`はファイルサイズと`ContentProvider`のペアを返します。そのまま`Post()`や`Put()`に渡せば、ファイルの中身がリクエストボディとしてそのまま送られます。

`ContentProvider`はファイルをチャンクごとに読み込むので、巨大なファイルでもメモリに全体を載せません。

## ファイルが開けなかったとき

`make_file_body()`は開けなかった場合、`size`を`0`、`provider`を空の関数オブジェクトとして返します。そのまま送信するとおかしな結果になるので、必ず`size`をチェックしてください。

> **Warning:** `make_file_body()`はContent-Lengthを最初に確定させる必要があるため、ファイルサイズをあらかじめ取得します。送信中にファイルサイズが変わる可能性がある場合は、このAPIには向きません。

> マルチパート形式で送りたい場合は[C07. ファイルをマルチパートフォームとしてアップロードする](c07-multipart-upload)を参照してください。
