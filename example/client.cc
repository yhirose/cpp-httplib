//
//  client.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>
#include <signal.h>

using namespace httplib;

int main(void)
{
    using namespace httplib;

    const char* hi = "/hi";

    Client cli("localhost", 1234);

    Response res;
    cli.get(hi, res);

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
