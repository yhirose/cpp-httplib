---
title: "T05. Access the Peer Certificate on the Server Side"
order: 46
status: "draft"
---

In an mTLS setup, you can read the client's certificate from inside a handler. Pull out the CN or SAN to identify the user or log the request.

## Basic usage

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

`req.peer_cert()` returns a `tls::PeerCert`. It's convertible to `bool`, so check whether a cert is present before using it.

## Available fields

From a `PeerCert`, you can get:

```cpp
auto cert = req.peer_cert();

std::string cn = cert.subject_cn();        // CN
std::string issuer = cert.issuer_name();   // issuer
std::string serial = cert.serial();        // serial number

time_t not_before, not_after;
cert.validity(not_before, not_after);      // validity period

auto sans = cert.sans();                   // SANs
for (const auto &san : sans) {
  std::cout << san.value << std::endl;
}
```

There's also a helper to check if a hostname is covered by the SAN list:

```cpp
if (cert.check_hostname("alice.corp.example.com")) {
  // matches
}
```

## Cert-based authorization

You can gate routes by CN or SAN.

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

Combined with a pre-request handler, you can keep all authorization logic in one place. See [S11. Authenticate per route with a pre-request handler](s11-pre-request).

## SNI (Server Name Indication)

cpp-httplib handles SNI automatically. If one server hosts multiple domains, SNI is used under the hood — but normally handlers don't need to care.

> **Warning:** `req.peer_cert()` only returns a meaningful value when mTLS is enabled and the client actually presented a certificate. For plain TLS, you get an empty `PeerCert`. Always do the `bool` check before using it.

> To set up mTLS, see [T04. Configure mTLS](t04-mtls).
