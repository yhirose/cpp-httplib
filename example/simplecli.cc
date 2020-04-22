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
  httplib::url::Options options;
  options.ca_cert_file_path = CA_CERT_FILE;
  // options.server_certificate_verification = true;

  auto res = httplib::url::Get("https://localhost:8080/hi", options);
#else
  auto res = httplib::url::Get("http://localhost:8080/hi");
#endif

  if (res) {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  }

  return 0;
}
