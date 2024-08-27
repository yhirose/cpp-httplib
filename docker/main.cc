//
//  main.cc
//
//  Copyright (c) 2024 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <cstdio>
#include <httplib.h>
#include <iostream>

using namespace httplib;
using namespace std;

auto error_html = R"(<html>
<head><title>%d %s</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>cpp-httplib/%s</center>
</body>
</html>
)";

int main(int argc, const char **argv) {
  Server svr;

  svr.set_error_handler([](const Request & /*req*/, Response &res) {
    char buf[BUFSIZ];
    snprintf(buf, sizeof(buf), error_html, res.status,
             status_message(res.status), CPPHTTPLIB_VERSION);
    res.set_content(buf, "text/html");
  });

  svr.set_mount_point("/", "./html");

  svr.listen("0.0.0.0", 80);

  return 0;
}
