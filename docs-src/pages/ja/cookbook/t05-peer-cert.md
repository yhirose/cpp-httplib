---
title: "T05. サーバー側でピア証明書を参照する"
order: 46
status: "draft"
---

mTLS構成では、接続してきたクライアントの証明書をハンドラの中で読めます。証明書のCN（Common Name）やSAN（Subject Alternative Name）を取り出して、ユーザーを特定したり、ログに残したりできます。

## 基本の使い方

```cpp
svr.Get("/me", [](const httplib::Request &req, httplib::Response &res) {
  auto cert = req.peer_cert();
  if (!cert) {
    res.status = 401;
    res.set_content("no client certificate", "text/plain");
    return;
  }

  auto cn = cert.subject_cn();
  res.set_content("hello, " + cn, "text/plain");
});
```

`req.peer_cert()`は`tls::PeerCert`オブジェクトを返します。`bool`に変換できるので、まずは証明書の有無を確認してから使います。

## 取り出せる情報

`PeerCert`からは、以下の情報を取得できます。

```cpp
auto cert = req.peer_cert();

std::string cn = cert.subject_cn();        // CN
std::string issuer = cert.issuer_name();   // 発行者
std::string serial = cert.serial();        // シリアル番号

time_t not_before, not_after;
cert.validity(not_before, not_after);      // 有効期間

auto sans = cert.sans();                   // SAN一覧
for (const auto &san : sans) {
  std::cout << san.value << std::endl;
}
```

ホスト名がSANに含まれるかを確認するヘルパーもあります。

```cpp
if (cert.check_hostname("alice.corp.example.com")) {
  // 一致
}
```

## 証明書ベースの認可

CNやSANを使って、ルート単位でアクセス制御できます。

```cpp
svr.set_pre_request_handler(
  [](const httplib::Request &req, httplib::Response &res) {
    auto cert = req.peer_cert();
    if (!cert) {
      res.status = 401;
      return httplib::Server::HandlerResponse::Handled;
    }

    if (req.matched_route.rfind("/admin", 0) == 0) {
      auto cn = cert.subject_cn();
      if (!is_admin_cn(cn)) {
        res.status = 403;
        return httplib::Server::HandlerResponse::Handled;
      }
    }

    return httplib::Server::HandlerResponse::Unhandled;
  });
```

Pre-requestハンドラと組み合わせれば、共通の認可ロジックを一箇所にまとめられます。詳しくはS11. Pre-request handlerでルート単位の認証を行うを参照してください。

## SNI（Server Name Indication）

クライアントが指定してきたサーバー名は、cpp-httplibが自動で処理します。同じサーバーで複数のドメインをホストする場合にSNIが使われますが、通常はハンドラ側で意識する必要はありません。

> **Warning:** `req.peer_cert()`は、mTLSが有効で、かつクライアントが証明書を提示した場合のみ有効な値を返します。通常のTLS接続では空の`PeerCert`が返ります。使う前に必ず`bool`チェックしてください。

> mTLSの設定方法はT04. mTLSを設定するを参照してください。
