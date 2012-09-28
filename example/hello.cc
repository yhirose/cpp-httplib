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
    Server svr("localhost", 1234);

    svr.get("/hi", [](Connection& c) {
        c.response.set_content("Hello World!");
    });

    svr.run();
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
