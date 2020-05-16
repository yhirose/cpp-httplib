//
//  simplecli.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>
#include <iostream>

#define CA_CERT_FILE "./ca-bundle.crt"

using namespace std;

int main(void) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto res = httplib::Client2("https://localhost:8080")
    .set_ca_cert_path(CA_CERT_FILE)
    // .enable_server_certificate_verification(true)
    .Get("/hi");
#else
  auto res = httplib::Client2("http://localhost:8080").Get("/hi");
#endif

  if (res) {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  }

  return 0;
}
