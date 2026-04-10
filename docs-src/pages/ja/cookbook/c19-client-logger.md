---
title: "C19. クライアントにログを設定する"
order: 19
status: "draft"
---

クライアントから送ったリクエストと受け取ったレスポンスをログに残したいときは、`set_logger()`を使います。エラーだけを拾いたいなら`set_error_logger()`が別に用意されています。

## リクエストとレスポンスをログに残す

```cpp
httplib::Client cli("https://api.example.com");

cli.set_logger([](const httplib::Request &req, const httplib::Response &res) {
  std::cout << req.method << " " << req.path
            << " -> " << res.status << std::endl;
});

auto res = cli.Get("/users");
```

`set_logger()`に渡したコールバックは、リクエストが完了するたびに呼ばれます。リクエストとレスポンスの両方を引数で受け取れるので、メソッドやパス、ステータスコード、ヘッダー、ボディなど好きな情報をログに残せます。

## エラーだけを拾う

ネットワーク層のエラーが起きたとき（`Error::Connection`など）は、`set_logger()`は呼ばれません。レスポンスが無いからです。こうしたエラーを拾いたいときは`set_error_logger()`を使います。

```cpp
cli.set_error_logger([](const httplib::Error &err, const httplib::Request *req) {
  std::cerr << "error: " << httplib::to_string(err);
  if (req) {
    std::cerr << " (" << req->method << " " << req->path << ")";
  }
  std::cerr << std::endl;
});
```

第2引数の`req`はヌルポインタのこともあります。リクエストを組み立てる前の段階で失敗した場合です。使う前に必ずヌルチェックしてください。

## 両方を組み合わせる

成功時は通常のログ、失敗時はエラーログ、という2本立てにすると便利です。

```cpp
cli.set_logger([](const auto &req, const auto &res) {
  std::cout << "[ok] " << req.method << " " << req.path
            << " " << res.status << std::endl;
});

cli.set_error_logger([](const auto &err, const auto *req) {
  std::cerr << "[ng] " << httplib::to_string(err);
  if (req) std::cerr << " " << req->method << " " << req->path;
  std::cerr << std::endl;
});
```

> **Note:** ログコールバックはリクエスト処理と同じスレッドで同期的に呼ばれます。重い処理を入れるとリクエストがその分遅くなるので、必要なら別スレッドのキューに流しましょう。
