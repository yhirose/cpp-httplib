---
title: "S07. マルチパートデータをストリーミングで受け取る"
order: 26
status: "draft"
---

大きなファイルをアップロードするハンドラを普通に書くと、`req.body`にリクエスト全体が載ってしまいメモリを圧迫します。`HandlerWithContentReader`を使うと、ボディをチャンクごとに受け取れます。

## 基本の使い方

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    if (req.is_multipart_form_data()) {
      content_reader(
        // 各パートのヘッダー
        [&](const httplib::FormData &file) {
          std::cout << "name: " << file.name
                    << ", filename: " << file.filename << std::endl;
          return true;
        },
        // 各パートのボディ（複数回呼ばれる）
        [&](const char *data, size_t len) {
          // ここでファイルに書き出すなど
          return true;
        });
    } else {
      // 普通のリクエストボディ
      content_reader([&](const char *data, size_t len) {
        return true;
      });
    }

    res.set_content("ok", "text/plain");
  });
```

`content_reader`は2通りの呼び方ができます。マルチパートのときは2つのコールバック（ヘッダー用とデータ用）を渡し、そうでないときは1つのコールバックだけを渡します。

## ファイルに直接書き出す

大きなファイルをそのままディスクに書き出す例です。

```cpp
svr.Post("/upload",
  [](const httplib::Request &req, httplib::Response &res,
     const httplib::ContentReader &content_reader) {
    std::ofstream ofs;

    content_reader(
      [&](const httplib::FormData &file) {
        if (!file.filename.empty()) {
          ofs.open("uploads/" + file.filename, std::ios::binary);
        }
        return static_cast<bool>(ofs);
      },
      [&](const char *data, size_t len) {
        ofs.write(data, len);
        return static_cast<bool>(ofs);
      });

    res.set_content("uploaded", "text/plain");
  });
```

メモリには常に小さなチャンクしか載らないので、ギガバイト級のファイルでも扱えます。

> **Warning:** `HandlerWithContentReader`を使うと、`req.body`は**空のまま**です。ボディはコールバック内で自分で処理してください。

> クライアント側でマルチパートを送る方法はC07. ファイルをマルチパートフォームとしてアップロードするを参照してください。
