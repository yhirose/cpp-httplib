httpsvrkit
==========

C++ HTTP sever library inspired by [Sinatra](http://www.sinatrarb.com/) 

[The Boost Software License 1.0](http://www.boost.org/LICENSE_1_0.txt)

Example
-------

    #include <httpsvrkit.h>

    int main(void) {
        HTTP_SERVER("localhost", 1234) {
            GET("/hi", {
                res.set_content("Hello World!");
            });
        }
    }

Copyright (c) 2012 Yuji Hirose. All rights reserved.
