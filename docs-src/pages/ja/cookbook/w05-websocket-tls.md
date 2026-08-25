---
title: "W05. wss接続でTLSを設定する"
order: 56
status: "draft"
---

`wss://`（WebSocket over TLS）接続のクライアント側TLS設定は、`SSLClient`とほぼ同じAPIです。`ws::WebSocketClient`は`ws://`と`wss://`を同じクラスで扱うので、`SSLClient`のような別クラスへの切り替えは不要です。

```cpp
httplib::ws::WebSocketClient ws1("ws://localhost:8080/ws");   // 平文
httplib::ws::WebSocketClient ws2("wss://localhost:8443/ws");  // TLS
```

## サーバー証明書の検証

`set_ca_cert_path()`で独自のCA証明書を指定できます。シグネチャは`SSLClient`と同じで、第1引数がCA証明書ファイル、第2引数がCA証明書ディレクトリ（省略可）です。

```cpp
httplib::ws::WebSocketClient ws("wss://internal.example.com/ws");
ws.set_ca_cert_path("/etc/ssl/certs/internal-ca.pem");

if (ws.connect()) {
  ws.send("hello");
}
```

証明書検証そのものを無効にしたい場合は`enable_server_certificate_verification(false)`が使えます。挙動の詳細は[T02. SSL証明書の検証を制御する](../t02-cert-verification)を参照してください。

## クライアント証明書を使う（mTLS）

`ws::WebSocketClient`には`PemMemory`構造体を受け取るコンストラクタがあり、`wss://`接続でクライアント証明書を提示できます。

```cpp
httplib::ws::WebSocketClient::PemMemory pem{};
pem.cert_pem = client_cert.data();
pem.cert_pem_len = client_cert.size();
pem.key_pem = client_key.data();
pem.key_pem_len = client_key.size();

httplib::ws::WebSocketClient ws("wss://api.example.com/ws", pem);

if (ws.connect()) {
  ws.send("hello");
}
```

`ws://`（非TLS）のURLに`PemMemory`を渡した場合は黙って無視されます。`SSLClient`と違い、ファイルパスから直接読み込むコンストラクタは用意されていないので、PEMをメモリ上に読み込んでから渡す必要があります。

mTLSの全体像（サーバー側の設定や用途の解説を含む）は[T04. mTLSを設定する](../t04-mtls)を参照してください。
