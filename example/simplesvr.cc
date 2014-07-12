//
//  simplesvr.cc
//
//  Copyright (c) 2013 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>
#include <iostream>

using namespace httplib;
using namespace std;

string dump_headers(const MultiMap& headers)
{
    string s;
    char buf[BUFSIZ];

    for (const auto& x: headers) {
       snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
       s += buf;
    }

    return s;
}

string log(const Request& req, const Response& res)
{
    string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s", req.method.c_str(), req.url.c_str());
    s += buf;

    string query;
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
    
    return s;
}

int main(int argc, const char** argv)
{
    if (argc > 1 && string("--help") == argv[1]) {
        cout << "usage: simplesvr [PORT] [DIR]" << endl;
        return 1;
    }

    Server svr;

    svr.set_error_handler([](const auto& req, auto& res) {
        const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    svr.set_logger([](const auto& req, const auto& res) {
        cout << log(req, res);
    });

    auto port = 80;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    auto base_dir = "./";
    if (argc > 2) {
        base_dir = argv[2];
    }

    svr.set_base_dir(base_dir);

    cout << "The server started at port " << port << "...";

    svr.listen("localhost", port);

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
