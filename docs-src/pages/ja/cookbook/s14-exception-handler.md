---
title: "S14. 例外をキャッチする"
order: 33
status: "draft"
---

ルートハンドラの中で例外が投げられても、cpp-httplibはサーバー全体を落とさずに500を返してくれます。ただ、デフォルトではエラー情報をクライアントにほとんど伝えません。`set_exception_handler()`を使うと、例外をキャッチして独自のレスポンスを組み立てられます。

## 基本の使い方

```cpp
svr.set_exception_handler(
  [](const httplib::Request &req, httplib::Response &res,
     std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content(std::string("error: ") + e.what(), "text/plain");
    } catch (...) {
      res.status = 500;
      res.set_content("unknown error", "text/plain");
    }
  });
```

ハンドラは`std::exception_ptr`を受け取るので、いったん`std::rethrow_exception()`で投げ直してから`catch`でキャッチするのが定石です。例外の型によってステータスコードやメッセージを変えられます。

## 自前の例外型で分岐する

独自の例外クラスを投げている場合、それを見て400や404にマッピングできます。

```cpp
struct NotFound : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct BadRequest : std::runtime_error {
  using std::runtime_error::runtime_error;
};

svr.set_exception_handler(
  [](const auto &req, auto &res, std::exception_ptr ep) {
    try {
      std::rethrow_exception(ep);
    } catch (const NotFound &e) {
      res.status = 404;
      res.set_content(e.what(), "text/plain");
    } catch (const BadRequest &e) {
      res.status = 400;
      res.set_content(e.what(), "text/plain");
    } catch (const std::exception &e) {
      res.status = 500;
      res.set_content("internal error", "text/plain");
    }
  });
```

ルートハンドラの中で`throw NotFound("user not found")`を投げるだけで、404が返るようになります。try/catchをハンドラごとに書かずに済むので、コードがすっきりします。

## set_error_handlerとの関係

`set_exception_handler()`は例外が発生した瞬間に呼ばれます。その後、`res.status`が4xx/5xxなら`set_error_handler()`も呼ばれます。順番は`exception_handler` → `error_handler`です。役割分担は次のとおりです。

- **例外ハンドラ**: 例外を解釈してステータスとメッセージを決める
- **エラーハンドラ**: 決まったステータスを見て、共通のテンプレートに整形する

> **Note:** 例外ハンドラを設定しないと、cpp-httplibはデフォルトの500レスポンスを返します。例外情報はログに残らないので、デバッグしたいなら必ず設定しましょう。
