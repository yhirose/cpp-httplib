//
//  hello.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>

int main(void)
{
    HTTP_SERVER("localhost", 1234) {

        // const httpsvrkit::Request& req
        // httpsvrkit::Response& res
        
        GET("/hello", {
            res.set_content("world");
        });

        GET("/url", {
            res.set_content(req.url);
        });
    }
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
