//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>
#include <cstdio>

using namespace httpsvrkit;

int dump_request(Context& cxt)
{
    auto& body = cxt.response.body;
    char buf[BUFSIZ];

    body += "================================\n";

    sprintf(buf, "Method: %s, URL: %s\n",
        cxt.request.method.c_str(),
        cxt.request.url.c_str());

    body += buf;

    //for (const auto& x : cxt.request.headers) {
    for (auto it = cxt.request.headers.begin(); it != cxt.request.headers.end(); ++it) {
       const auto& x = *it;
       sprintf(buf, "%s: %s\n", x.first.c_str(), x.second.c_str());
       body += buf;
    }

    body += "================================\n";

    return 200;
}

int main(void)
{
    Server svr;

    svr.get("/", [](Context& cxt) -> int {
        dump_request(cxt);
        return 200;
    });

    svr.post("/item", [](Context& cxt) -> int {
        dump_request(cxt);
        cxt.response.body += cxt.request.url;
        return 200;
    });

    svr.get("/item/([^/]+)", [](Context& cxt) -> int {
        dump_request(cxt);
        cxt.response.body += cxt.request.params[0];
        return 200;
    });

    svr.run("localhost", 1234);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
