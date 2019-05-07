//
//  client.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <iostream>

#define CA_CERT_FILE "./ca-bundle.crt"

using namespace std;

int main(void) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli("localhost", 8080);
  // httplib::SSLClient cli("google.com");
  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.skip_server_certificate_verification(true);
#else
  httplib::Client cli("localhost", 8080);
#endif

  auto res = cli.Get("/hi");
  if (res) {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  } else {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto result = cli.get_openssl_verify_result();
    if (result) {
        cout << "verify error: " << X509_verify_cert_error_string(result) << endl;
    }
#endif
  }

  return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
