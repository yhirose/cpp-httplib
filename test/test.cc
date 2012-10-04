
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
    auto val = get_header_value_text(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/plain", val);
}

TEST(GetHeaderValueTest, DefaultValueInt)
{
    MultiMap map = {{"Dummy","Dummy"}};
    auto val = get_header_value_int(map, "Content-Length", 100);
    ASSERT_EQ(100, val);
}

TEST(GetHeaderValueTest, RegularValue)
{
    MultiMap map = {{"Content-Type","text/html"}, {"Dummy", "Dummy"}};
    auto val = get_header_value_text(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, RegularValueInt)
{
    MultiMap map = {{"Content-Length","100"}, {"Dummy", "Dummy"}};
    auto val = get_header_value_int(map, "Content-Length", 0);
    ASSERT_EQ(100, val);
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest() : svr_(host_, port_) {
    }

    virtual void SetUp() {
        svr_.get(url_, [&](httplib::Connection& c) {
            c.response.set_content(content_, mime_);
        });
        f_ = async([&](){ svr_.run(); });
    }

    virtual void TearDown() {
        svr_.stop();
        f_.get();
    }

    const char* host_ = "localhost";
    int         port_ = 1914;
    const char* url_ = "/hi";
    const char* content_ = "Hello World!";
    const char* mime_ = "text/plain";

    Server            svr_;
    std::future<void> f_;
};

TEST_F(ServerTest, GetMethod200)
{
    Response res;
    bool ret = Client(host_, port_).get(url_, res);
    ASSERT_EQ(true, ret);
    ASSERT_EQ(200, res.status);
    ASSERT_EQ(content_, res.body);
}

TEST_F(ServerTest, GetMethod404)
{
    Response res;
    bool ret = Client(host_, port_).get("/invalid", res);
    ASSERT_EQ(false, ret);
    ASSERT_EQ(404, res.status);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
