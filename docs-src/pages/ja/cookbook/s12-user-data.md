---
title: "S12. res.user_dataでハンドラ間データを渡す"
order: 31
status: "draft"
---

Pre-requestハンドラで認証トークンをデコードして、その結果をルートハンドラで使いたい。こういう「ハンドラ間のデータ受け渡し」は、`res.user_data`に任意の型を入れて解決します。

## 基本の使い方

```cpp
struct AuthUser {
  std::string id;
  std::string name;
  bool is_admin;
};

svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    auto token = req.get_header_value("Authorization");
    auto user = decode_token(token); // 認証トークンをデコード
    res.user_data.set("user", user);
    return httplib::Server::HandlerResponse::Unhandled;
  });

svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto *user = res.user_data.get<AuthUser>("user");
  if (!user) {
    res.status = 401;
    return;
  }
  res.set_content("Hello, " + user->name, "text/plain");
});
```

`user_data.set()`で任意の型の値を保存し、`user_data.get<T>()`で取り出します。型を正しく指定しないと`nullptr`が返るので注意してください。

## よくある型

`std::string`、数値、構造体、`std::shared_ptr`など、コピーかムーブできる値なら何でも入れられます。

```cpp
res.user_data.set("user_id", std::string{"42"});
res.user_data.set("is_admin", true);
res.user_data.set("started_at", std::chrono::steady_clock::now());
```

## どこで設定し、どこで読むか

設定する側は`set_pre_routing_handler()`か`set_pre_request_handler()`、読む側は通常のルートハンドラ、という流れが一般的です。Pre-requestのほうがルーティング後に呼ばれるので、`req.matched_route`と組み合わせて「このルートにマッチしたときだけセット」という書き方ができます。

## 注意点

`user_data`は`Response`に乗っています（`req.user_data`ではありません）。これは、ハンドラには`Response&`として可変参照が渡されるためです。一見不思議ですが、「ハンドラ間で共有する可変コンテキスト」として覚えておくと素直です。

> **Warning:** `user_data.get<T>()`は型が一致しないと`nullptr`を返します。保存時と取得時で同じ型を指定してください。`AuthUser`で入れて`const AuthUser`で取ろうとすると失敗します。
