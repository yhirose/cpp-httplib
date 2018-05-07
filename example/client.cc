//
//  client.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <iostream>

using namespace std;

int main(void)
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    httplib::SSLClient cli("localhost", 8080);
#else
    httplib::Client cli("localhost", 8080);
#endif

    auto res = cli.Get("/hi");
    if (res) {
        cout << res->status << endl;
        cout << res->get_header_value("Content-Type") << endl;
        cout << res->body << endl;
    }

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
