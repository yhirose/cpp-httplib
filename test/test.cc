
#include <gtest/gtest.h>
#include <httplib.h>
#include <future>
#include <iostream>

using namespace std;
using namespace httplib;

TEST(SplitTest, ParseQueryString)
{
    string s = "key1=val1&key2=val2&key3=val3";
    map<string, string> dic;

    split(&s[0], &s[s.size()], '&', [&](const char* b, const char* e) {
        string key, val;
        split(b, e, '=', [&](const char* b, const char* e) {
            if (key.empty()) {
                key.assign(b, e);
            } else {
                val.assign(b, e);
            }
        });
        dic[key] = val;
    });

    ASSERT_EQ("val1", dic["key1"]);
    ASSERT_EQ("val2", dic["key2"]);
    ASSERT_EQ("val3", dic["key3"]);
}

TEST(SocketTest, OpenClose)
{
    socket_t sock = create_server_socket("localhost", 1914);
    ASSERT_NE(-1, sock);

    auto ret = close_server_socket(sock);
    ASSERT_EQ(0, ret);
}

TEST(GetHeaderValueTest, DefaultValue)
{
    MultiMap map = {{"Dummy","Dummy"}};
    auto val = get_header_value(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/plain", val);
}

TEST(GetHeaderValueTest, RegularValue)
{
    MultiMap map = {{"Content-Type","text/html"}, {"Dummy", "Dummy"}};
    auto val = get_header_value(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/html", val);
}

TEST(ServerTest, GetMethod)
{
    const char* host = "localhost";
    int port = 1914;
    const char* url = "/hi";
    const char* content = "Hello World!";

    Server svr(host, port);

    svr.get(url, [&](httplib::Connection& c) {
        c.response.set_content(content);
    });

    //svr.on_ready([&]() { svr.stop(); });
    
    auto f = async([&](){ svr.run(); });

    sleep(1);

    Client cli(host, port);

    Response res;
    cli.get(url, res);
    EXPECT_EQ(content, res.body);

    svr.stop();
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
