---
title: "C01. レスポンスボディを取得する / ファイルに保存する"
order: 1
status: "draft"
---

## 文字列として取得する

```cpp
httplib::Client cli("http://localhost:8080");
auto res = cli.Get("/hello");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

`res->body`は`std::string`なので、そのまま使えます。レスポンス全体がメモリに読み込まれます。

> **Warning:** 大きなファイルを`res->body`で受け取ると、まるごとメモリに載ってしまいます。サイズが大きい場合は次の`ContentReceiver`を使いましょう。

## ファイルに保存する

```cpp
httplib::Client cli("http://localhost:8080");

std::ofstream ofs("output.bin", std::ios::binary);
if (!ofs) {
  std::cerr << "Failed to open file" << std::endl;
  return 1;
}

auto res = cli.Get("/large-file",
  [&](const char *data, size_t len) {
    ofs.write(data, len);
    return static_cast<bool>(ofs);
  });
```

`ContentReceiver`を使うと、データをチャンクごとに受け取れます。ボディ全体をメモリに溜めずにファイルへ書き出せるので、大きなファイルのダウンロードにぴったりです。

コールバックから`false`を返すと、ダウンロードを途中で止められます。上の例では`ofs`への書き込みが失敗したら自動的に中断します。

> **Detail:** ダウンロード前にContent-Lengthなどのレスポンスヘッダーを確認したいときは、`ResponseHandler`を組み合わせましょう。
>
> ```cpp
> auto res = cli.Get("/large-file",
>   [](const httplib::Response &res) {
>     auto len = res.get_header_value("Content-Length");
>     std::cout << "Size: " << len << std::endl;
>     return true; // falseを返すとダウンロードを中止
>   },
>   [&](const char *data, size_t len) {
>     ofs.write(data, len);
>     return static_cast<bool>(ofs);
>   });
> ```
>
> `ResponseHandler`はヘッダー受信後、ボディ受信前に呼ばれます。`false`を返せばダウンロード自体をスキップできます。

> ダウンロードの進捗を表示したい場合はC11. 進捗コールバックを使うを参照してください。
