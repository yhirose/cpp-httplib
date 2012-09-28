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
            c.response.set_content("Hello World!");
        });

        svr.run();
    }

Copyright (c) 2012 Yuji Hirose. All rights reserved.
