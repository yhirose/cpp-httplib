//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>

#ifdef _WIN32
#define snprintf sprintf_s
#endif

std::string dump_headers(const httplib::MultiMap& headers)
{
    std::string s;
    char buf[BUFSIZ];

    for (auto it = headers.begin(); it != headers.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
       s += buf;
    }

    return s;
}

std::string log(const httplib::Connection& c)
{
    const auto& req = c.request;
    const auto& res = c.response;

    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s", req.method.c_str(), req.url.c_str());
    s += buf;

    std::string query;
    for (auto it = req.query.begin(); it != req.query.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%c%s=%s",
           (it == req.query.begin()) ? '?' : '&', x.first.c_str(), x.second.c_str());
       query += buf;
    }
    snprintf(buf, sizeof(buf), "%s\n", query.c_str());
    s += buf;

    s += dump_headers(req.headers);

    s += "--------------------------------\n";

    snprintf(buf, sizeof(buf), "%d\n", res.status);
    s += buf;
    s += dump_headers(res.headers);
    
    if (!res.body.empty()) {
        s += res.body;
    }

    s += "\n";

    return s;
}

int main(void)
{
    using namespace httplib;

    const char* hi = "/hi";

    Server svr("localhost", 8080);

    svr.get("/", [=](Connection& c) {
        c.response.set_redirect(hi);
    });

    svr.get("/hi", [](Connection& c) {
        c.response.set_content("Hello World!", "text/plain");
    });

    svr.get("/dump", [](Connection& c) {
        c.response.set_content(dump_headers(c.request.headers), "text/plain");
    });

    svr.set_error_handler([](httplib::Connection& c) {
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), "<p>Error Status: <span style='color:red;'>%d</span></p>", c.response.status);
        c.response.set_content(buf, "text/html");
    });

    svr.set_logger([](const Connection& c) {
        printf("%s", log(c).c_str());
    });

    svr.run();

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
