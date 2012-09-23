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

    svr.post("/", [](const Request& /*req*/, Response& res) {
        res.body_ = "<html><head></head><body><ul></ul></body></html>";
    });

    svr.post("/item", [](const Request& req, Response& res) {
        res.body_ = req.pattern_;
    });

    svr.get("/item/:name", [](const Request& req, Response& res) {
        try {
            res.body_ = req.params_.at("name");
        } catch (...) {
            // Error...
        }
    });

    svr.run("0.0.0.0", 1234);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
