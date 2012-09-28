//
//  hello.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>

int main(void)
{
    HTTP_SERVER("localhost", 1234) /* svr_ */ {
        GET("/hi", /* req_, res_ */ {
            res_.set_content("Hello World!");
        });
    }
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
