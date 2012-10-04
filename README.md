cpp-httplib
===========

A C++ HTTP library.

[The Boost Software License 1.0](http://www.boost.org/LICENSE_1_0.txt)

Server Example
--------------

Inspired by [Sinatra](http://www.sinatrarb.com/) 

    #include <httplib.h>
    using namespace httplib;

    int main(void)
    {
        Server svr("localhost", 1234);

        svr.get("/hi", [](Connection& c) {
            c.response.set_content("Hello World!", "text/plain");
        });

        svr.run();
    }

Client Example
--------------

    #include <httplib.h>
    #include <iostream>
    using namespace httplib;

    int main(void)
    {
        Client cli("localhost", 1234);

        auto res = cli.get("/hi");
        if (res && res->status == 200) {
            std::cout << res->body << std::endl;
        }
    }

Copyright (c) 2012 Yuji Hirose. All rights reserved.
