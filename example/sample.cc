//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>
#include <signal.h>

using namespace httplib;

template<typename Fn> void signal(int sig, Fn fn)
{
    static std::function<void ()> signal_handler_;
    struct SignalHandler { static void fn(int sig) { signal_handler_(); } };
    signal_handler_ = fn;
    signal(sig, SignalHandler::fn);
}

int main(void)
{
    using namespace httplib;

    const char* hi = "/hi";

    Server svr("localhost", 1234);

    svr.get("/", [=](Connection& c) {
        c.response.set_redirect(hi);
    });

    svr.get("/hi", [](Connection& c) {
        c.response.set_content("Hello World!");
    });

    svr.get("/dump", [](Connection& c) {
        c.response.set_content(dump_request(c));
    });

    signal(SIGINT, [&]() { svr.stop(); });

    svr.run();
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
