---
title: "S03. パスパラメーターを使う"
order: 22
status: "draft"
---

REST APIでよく使う`/users/:id`のような動的なパスは、パスパターンに`:name`を書くだけで使えます。マッチした値は`req.path_params`に入ります。

## 基本の使い方

```cpp
svr.Get("/users/:id", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.path_params.at("id");
  res.set_content("user id: " + id, "text/plain");
});
```

`/users/42`にアクセスすると、`req.path_params["id"]`に`"42"`が入ります。`path_params`は`std::unordered_map<std::string, std::string>`なので、`at()`で取り出します。

## 複数のパラメーター

パラメーターはいくつでも書けます。

```cpp
svr.Get("/orgs/:org/repos/:repo", [](const httplib::Request &req, httplib::Response &res) {
  auto org = req.path_params.at("org");
  auto repo = req.path_params.at("repo");
  res.set_content(org + "/" + repo, "text/plain");
});
```

`/orgs/anthropic/repos/cpp-httplib`のようなパスがマッチします。

## 正規表現パターン

もっと柔軟にマッチさせたいときは、`std::regex`ベースのパターンも使えます。

```cpp
svr.Get(R"(/users/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
  auto id = req.matches[1];
  res.set_content("user id: " + std::string(id), "text/plain");
});
```

パターンに括弧を使うと、マッチした部分が`req.matches`に入ります。`req.matches[0]`はパス全体、`req.matches[1]`以降がキャプチャです。

## どちらを使うか

- 単純なIDやスラッグなら`:name`でじゅうぶん。読みやすく、型が自明です
- 数値のみ、UUIDのみといった形式をURLで絞りたいなら正規表現が便利
- 両方を混ぜると混乱するので、プロジェクト内ではどちらかに統一するのがおすすめです

> **Note:** パスパラメーターは文字列として入ってくるので、整数として使いたい場合は`std::stoi()`などで変換してください。変換失敗のハンドリングも忘れずに。
