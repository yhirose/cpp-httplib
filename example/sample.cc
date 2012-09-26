//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httpsvrkit.h>
#include <cstdio>

using namespace httpsvrkit;

std::string dump_request(Context& cxt)
{
    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    sprintf(buf, "Method: %s\n", cxt.request.method.c_str());
    s += buf;

    sprintf(buf, "URL: %s\n", cxt.request.url.c_str());
    s += buf;

    std::string query;
    for (auto it = cxt.request.query.begin(); it != cxt.request.query.end(); ++it) {
       const auto& x = *it;
       sprintf(buf, "(%s:%s)", x.first.c_str(), x.second.c_str());
       query += buf;
    }
    sprintf(buf, "QUERY: %s\n", query.c_str());
    s += buf;

    //for (const auto& x : cxt.request.headers) {
    for (auto it = cxt.request.headers.begin(); it != cxt.request.headers.end(); ++it) {
       const auto& x = *it;
       sprintf(buf, "%s: %s\n", x.first.c_str(), x.second.c_str());
       s += buf;
    }

    s += "================================\n";

    return s;
}

int main(void)
{
    if (true) {
        const char* s = "abcde";

        // DSL style
        HTTP_SERVER("localhost", 1234) {

            GET("/", {
                res.set_redirect("/home");
            });

            GET("/home", {
                res.set_content(dump_request(cxt));
            });

            GET("/abcde", {
                res.set_content(s);
            });
        }
    } else {
        // Regular style
        Server svr("localhost", 1234);

        svr.get("/", [](Context& cxt) {
            cxt.response.set_redirect("/home");
        });

        svr.get("/home", [](Context& cxt) {
            cxt.response.set_content(dump_request(cxt));
        });

        svr.post("/item", [](Context& cxt) {
            cxt.response.set_content(dump_request(cxt));
        });

        svr.get("/item/([^/]+)", [](Context& cxt) {
            cxt.response.set_content(dump_request(cxt));
        });

        svr.run();
    }
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
