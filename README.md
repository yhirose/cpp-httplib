cpp-httplib
===========

A C++11 header-only HTTP library.

[The Boost Software License 1.0](http://www.boost.org/LICENSE_1_0.txt)

It's extremely easy to setup. Just include **httplib.h** file in your code!

Server Example
--------------

Inspired by [Sinatra](http://www.sinatrarb.com/) and [express](https://github.com/visionmedia/express).

```c++
#include <httplib.h>

int main(void)
{
    using namespace httplib;

    Server svr;

    svr.get("/hi", [](const auto& req, auto& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.get(R"(/numbers/(\d+))", [&](const auto& req, auto& res) {
        auto numbers = req.matches[1];
        res.set_content(numbers, "text/plain");
    });

    svr.listen("localhost", 1234);
}
```

Client Example
--------------

```c++
#include <httplib.h>
#include <iostream>

int main(void)
{
    httplib::Client cli("localhost", 1234);

    auto res = cli.get("/hi");
    if (res && res->status == 200) {
        std::cout << res->body << std::endl;
    }
}
```

Copyright (c) 2014 Yuji Hirose. All rights reserved.
