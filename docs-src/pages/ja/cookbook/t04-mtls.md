---
title: "T04. mTLSを設定する"
order: 45
status: "draft"
---

通常のTLSはサーバー証明書だけを検証しますが、**mTLS**（mutual TLS、相互TLS）ではクライアントも証明書を提示し、サーバーがそれを検証します。API間通信のゼロトラスト化や、社内システムの認証でよく使われるパターンです。

## サーバー側の設定

`SSLServer`のコンストラクタ第3、第4引数に、クライアント証明書を検証するためのCA証明書を渡します。

```cpp
httplib::SSLServer svr(
  "server-cert.pem",    // サーバー証明書
  "server-key.pem",     // サーバー秘密鍵
  "client-ca.pem",      // クライアント証明書を検証するCA
  nullptr               // CAディレクトリ（省略）
);

svr.Get("/", [](const httplib::Request &req, httplib::Response &res) {
  res.set_content("authenticated", "text/plain");
});

svr.listen("0.0.0.0", 443);
```

この設定だと、クライアント証明書が`client-ca.pem`で署名されていない接続はハンドシェイクの段階で拒否されます。ハンドラまで到達した時点で、クライアントはすでに認証済みです。

## メモリ上のPEMで設定する

```cpp
httplib::SSLServer::PemMemory pem{};
pem.cert_pem = server_cert.data();
pem.cert_pem_len = server_cert.size();
pem.key_pem = server_key.data();
pem.key_pem_len = server_key.size();
pem.client_ca_pem = client_ca.data();
pem.client_ca_pem_len = client_ca.size();

httplib::SSLServer svr(pem);
```

環境変数やシークレットマネージャから読み込む場合はこちらが便利です。

## クライアント側の設定

クライアント側では、`SSLClient`のコンストラクタにクライアント証明書と秘密鍵を渡します。

```cpp
httplib::SSLClient cli("api.example.com", 443,
                       "client-cert.pem",
                       "client-key.pem");

auto res = cli.Get("/");
```

`Client`ではなく`SSLClient`を直接使う点に注意してください。秘密鍵にパスワードがある場合は第5引数で渡せます。

## ハンドラからクライアント情報を取得する

ハンドラの中で、どのクライアントが接続してきたかを確認したいときは`req.peer_cert()`を使います。詳しくは[T05. サーバー側でピア証明書を参照する](t05-peer-cert)を参照してください。

## 用途

- **マイクロサービス間通信**: サービスごとに証明書を発行して、証明書で認証する
- **IoTデバイスの管理**: デバイスに証明書を焼き込み、APIへのアクセス制御に使う
- **社内VPNの代替**: 公開されているエンドポイントに証明書認証をかけて、社内リソースへ安全にアクセスさせる

> **Note:** クライアント証明書の発行と失効管理は、普通のパスワード認証より運用コストが高いです。内部PKIを回すか、ACME（Let's Encryptなど）系のツールで自動化する体制が必要です。
