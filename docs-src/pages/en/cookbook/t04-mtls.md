---
title: "T04. Configure mTLS"
order: 45
status: "draft"
---

Regular TLS verifies the server certificate only. **mTLS** (mutual TLS) adds the other direction: the client presents a certificate too, and the server verifies it. It's common for zero-trust API-to-API traffic and internal system authentication.

## Server side

Pass the CA used to verify client certificates as the third (and fourth) argument to `SSLServer`.

```cpp
httplib::SSLServer svr(
  "server-cert.pem",    // server certificate
  "server-key.pem",     // server private key
  "client-ca.pem",      // CA that signs valid client certs
  nullptr               // CA directory (none)
);

svr.Get("/", [](const httplib::Request &req, httplib::Response &res) {
  res.set_content("authenticated", "text/plain");
});

svr.listen("0.0.0.0", 443);
```

With this, any connection whose client certificate isn't signed by `client-ca.pem` is rejected at the handshake. By the time a handler runs, the client is already authenticated.

## Configure with in-memory PEM

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

This is the clean way when you load certificates from environment variables or a secrets manager.

## Client side

On the client side, pass the client certificate and key to `SSLClient`.

```cpp
httplib::SSLClient cli("api.example.com", 443,
                       "client-cert.pem",
                       "client-key.pem");

auto res = cli.Get("/");
```

Note you're using `SSLClient` directly, not `Client`. If the private key has a password, pass it as the fifth argument.

## Read client info from a handler

To see which client connected from inside a handler, use `req.peer_cert()`. Details in [T05. Access the peer certificate on the server](t05-peer-cert).

## Use cases

- **Microservice-to-microservice calls**: Issue a cert per service, use the cert as identity
- **IoT device management**: Burn a cert into each device and use it to gate API access
- **An alternative to internal VPN**: Put cert-based auth in front of public endpoints so internal resources can be reached safely

> **Note:** Issuing and revoking client certificates is more operational work than password-based auth. You'll need either an internal PKI setup or an automated flow using ACME-family tools.
