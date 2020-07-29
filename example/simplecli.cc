//
//  simplecli.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>
#include <iostream>

using namespace std;

int main(void) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto scheme_host_port = "https://localhost:8080";
#else
  auto scheme_host_port = "http://localhost:8080";
#endif

  auto res = httplib::Client2(scheme_host_port).Get("/hi");

  if (res) {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  }

  return 0;
}
