//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>
#include <cstdio>

using namespace httpsvrkit;

int main(void)
{
    const char* hi = "/hi";

    HTTP_SERVER("localhost", 1234) {

        GET("/", {
            res.set_redirect(hi);
        });

        GET("/hi", {
            res.set_content("Hello World!");
        });

        GET("/dump", {
            res.set_content(dump_request(cxt));
        });
    }
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
