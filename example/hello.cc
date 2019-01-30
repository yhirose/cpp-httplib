//
//  hello.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
using namespace httplib;

int main(void)
{
    Server svr;

    svr.Get("/hi", [](const Request& /*req*/, Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.listen("localhost", 1234);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
