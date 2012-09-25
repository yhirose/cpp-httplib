//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>
#include <cstdio>

int main(void)
{
    using namespace httpsvrkit;

    Server svr;

    svr.get("/", [](Context& cxt) {
        cxt.response.body = "<html><head></head><body><ul></ul></body></html>";
    });

    svr.post("/item", [](Context& cxt) {
        cxt.response.body = cxt.request.pattern;
    });

    svr.get("/item/:name", [](Context& cxt) {
         cxt.response.body = cxt.request.params.at("name");
    });

    svr.run("localhost", 1234);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
