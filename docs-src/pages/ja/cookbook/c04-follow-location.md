---
title: "C04. リダイレクトを追従する"
order: 4
status: "draft"
---

cpp-httplibはデフォルトではリダイレクト（HTTP 3xx）を追従しません。サーバーから`302 Found`が返ってきても、そのままステータスコード302のレスポンスとして受け取ります。

自動で追従してほしいときは、`set_follow_location(true)`を呼びましょう。

## リダイレクトを追従する

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/old-path");
if (res && res->status == 200) {
  std::cout << res->body << std::endl;
}
```

`set_follow_location(true)`を設定すると、`Location`ヘッダーを見て新しいURLに自動でリクエストを投げ直します。最終的なレスポンスが`res`に入ります。

## HTTPからHTTPSへのリダイレクト

```cpp
httplib::Client cli("http://example.com");
cli.set_follow_location(true);

auto res = cli.Get("/");
```

多くのサイトはHTTPアクセスをHTTPSへリダイレクトします。`set_follow_location(true)`を有効にしておけば、こうしたケースも透過的に扱えます。スキームやホストが変わっても自動で追従します。

リダイレクト先が別のオリジン（スキーム、ホスト、ポートのどれかが違う）の場合、`Authorization`、`Cookie`、`Proxy-Authorization`ヘッダーは外され、`set_basic_auth()`などで設定した認証情報も送られません。クライアント証明書も提示しません。それ以外のヘッダーはデフォルトヘッダーも含めてそのまま送られ、タイムアウト、ペイロードの上限、TLSの検証設定も引き継がれます。

> **Warning:** HTTPSへのリダイレクトを追従するには、cpp-httplibをOpenSSL（または他のTLSバックエンド）付きでビルドしておく必要があります。TLSサポートがないと、HTTPSへのリダイレクトは失敗します。

> **Note:** リダイレクトを追従すると、リクエストの実行時間は伸びます。タイムアウトの設定は[C12. タイムアウトを設定する](../c12-timeouts)を参照してください。
