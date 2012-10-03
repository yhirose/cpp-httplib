//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>
#include <signal.h>

template<typename Fn> void signal(int sig, Fn fn)
{
    static std::function<void ()> signal_handler_;
    struct SignalHandler { static void fn(int sig) { signal_handler_(); } };
    signal_handler_ = fn;
    signal(sig, SignalHandler::fn);
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

    s += httplib::dump_headers(req.headers);

    s += "--------------------------------\n";

    snprintf(buf, sizeof(buf), "%d\n", res.status);
    s += buf;
    s += httplib::dump_headers(res.headers);
    
    if (!res.body.empty()) {
        s += res.body;
    }

    s += "\n";

    return s;
}

inline void error_handler(httplib::Connection& c)
{
    char buf[BUFSIZ];
    snprintf(buf, sizeof(buf), "Error Status: %d\r\n", c.response.status);
    c.response.set_content(buf);
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
        c.response.set_content("Hello World!");
    });

    svr.get("/dump", [](Connection& c) {
        c.response.set_content(httplib::dump_headers(c.request.headers));
    });

    svr.error(error_handler);

    svr.set_logger([](const Connection& c) {
        printf("%s", log(c).c_str());
    });

    signal(SIGINT, [&]() { svr.stop(); });

    svr.run();

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
