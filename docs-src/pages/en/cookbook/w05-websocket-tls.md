---
title: "W05. Configure TLS for wss:// Connections"
order: 55
status: "draft"
---

Client-side TLS configuration for `wss://` (WebSocket over TLS) connections uses almost the same API as `SSLClient`. `ws::WebSocketClient` handles both `ws://` and `wss://` through the same class, so there's no separate class to switch to the way `SSLClient` requires.

```cpp
httplib::ws::WebSocketClient ws1("ws://localhost:8080/ws");   // plaintext
httplib::ws::WebSocketClient ws2("wss://localhost:8443/ws");  // TLS
```

## Verifying the server certificate

Use `set_ca_cert_path()` to point at your own CA certificate. The signature matches `SSLClient`: the first argument is the CA certificate file, the second is an optional CA directory.

```cpp
httplib::ws::WebSocketClient ws("wss://internal.example.com/ws");
ws.set_ca_cert_path("/etc/ssl/certs/internal-ca.pem");

if (ws.connect()) {
  ws.send("hello");
}
```

To disable certificate verification entirely, use `enable_server_certificate_verification(false)`. For details on that behavior, see [T02. Control SSL Certificate Verification](../t02-cert-verification).

## Presenting a client certificate (mTLS)

`ws::WebSocketClient` has a constructor overload that takes a `PemMemory` struct, letting `wss://` connections present a client certificate.

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

Passing `PemMemory` to a `ws://` (non-TLS) URL is silently ignored. There's no constructor that reads the cert files directly, so unlike `SSLClient` you always load the PEM into memory yourself before passing it in.

For the full mTLS picture, including server-side setup and use cases, see [T04. Configure mTLS](../t04-mtls).
