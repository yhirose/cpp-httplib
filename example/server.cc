//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>

using namespace httplib;

std::string dump_headers(const MultiMap& headers)
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

std::string log(const Request& req, const Response& res)
{
    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s", req.method.c_str(), req.url.c_str());
    s += buf;

    std::string query;
    for (auto it = req.params.begin(); it != req.params.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%c%s=%s",
           (it == req.params.begin()) ? '?' : '&', x.first.c_str(), x.second.c_str());
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
    Server svr;

    svr.get("/", [=](const auto& req, auto& res) {
        res.set_redirect("/hi");
    });

    svr.get("/hi", [](const auto& req, auto& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.get("/dump", [](const auto& req, auto& res) {
        res.set_content(dump_headers(req.headers), "text/plain");
    });

    svr.get("/stop", [&](const auto& req, auto& res) {
        svr.stop();
    });

    svr.set_error_handler([](const auto& req, auto& res) {
        const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    svr.set_logger([](const auto& req, const auto& res) {
        printf("%s", log(req, res).c_str());
    });

    svr.listen("localhost", 8080);

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
