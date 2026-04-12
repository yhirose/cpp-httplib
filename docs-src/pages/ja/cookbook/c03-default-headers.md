---
title: "C03. デフォルトヘッダーを設定する"
order: 3
status: "draft"
---

同じヘッダーを毎回のリクエストに付けたいときは、`set_default_headers()`を使います。一度設定すれば、そのクライアントから送るすべてのリクエストに自動で付与されます。

## 基本の使い方

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Accept", "application/json"},
  {"User-Agent", "my-app/1.0"},
});

auto res = cli.Get("/users");
```

`Accept`や`User-Agent`のように、APIを呼ぶたびに必要なヘッダーをまとめて登録できます。リクエストごとに指定する手間が省けます。

## Bearerトークンを毎回付ける

```cpp
httplib::Client cli("https://api.example.com");

cli.set_default_headers({
  {"Authorization", "Bearer " + token},
  {"Accept", "application/json"},
});

auto res1 = cli.Get("/me");
auto res2 = cli.Get("/projects");
```

認証トークンを一度セットしておけば、以降のリクエストで自動的に送られます。複数のエンドポイントを叩くAPIクライアントを書くときに便利です。

> **Note:** `set_default_headers()`は既存のデフォルトヘッダーを**上書き**します。あとから1つだけ追加したい場合でも、全体を渡し直してください。

## リクエスト単位のヘッダーと組み合わせる

デフォルトヘッダーを設定していても、個別のリクエストで追加のヘッダーを渡せます。

```cpp
httplib::Headers headers = {
  {"X-Request-ID", "abc-123"},
};
auto res = cli.Get("/users", headers);
```

リクエスト単位で渡したヘッダーはデフォルトヘッダーに**追加**されます。両方がサーバーに送られます。

> Bearerトークンを使った認証の詳細は[C06. BearerトークンでAPIを呼ぶ](c06-bearer-token)を参照してください。
