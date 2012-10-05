
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

    detail::split(&s[0], &s[s.size()], '&', [&](const char* b, const char* e) {
        string key, val;
        detail::split(b, e, '=', [&](const char* b, const char* e) {
            if (key.empty()) {
                key.assign(b, e);
            } else {
                val.assign(b, e);
            }
        });
        dic[key] = val;
    });

    EXPECT_EQ("val1", dic["key1"]);
    EXPECT_EQ("val2", dic["key2"]);
    EXPECT_EQ("val3", dic["key3"]);
}

TEST(ParseQueryTest, ParseQueryString)
{
    string s = "key1=val1&key2=val2&key3=val3";
    map<string, string> dic;

    detail::parse_query_text(&s[0], &s[s.size()], dic);

    EXPECT_EQ("val1", dic["key1"]);
    EXPECT_EQ("val2", dic["key2"]);
    EXPECT_EQ("val3", dic["key3"]);
}

TEST(SocketTest, OpenClose)
{
    socket_t sock = detail::create_server_socket("localhost", 1914);
    ASSERT_NE(-1, sock);

    auto ret = detail::shutdown_and_close_socket(sock);
    EXPECT_EQ(0, ret);
}

TEST(GetHeaderValueTest, DefaultValue)
{
    MultiMap map = {{"Dummy","Dummy"}};
    auto val = detail::get_header_value_text(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/plain", val);
}

TEST(GetHeaderValueTest, DefaultValueInt)
{
    MultiMap map = {{"Dummy","Dummy"}};
    auto val = detail::get_header_value_int(map, "Content-Length", 100);
    EXPECT_EQ(100, val);
}

TEST(GetHeaderValueTest, RegularValue)
{
    MultiMap map = {{"Content-Type","text/html"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value_text(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, RegularValueInt)
{
    MultiMap map = {{"Content-Length","100"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value_int(map, "Content-Length", 0);
    EXPECT_EQ(100, val);
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest() : svr_(HOST, PORT), cli_(HOST, PORT) {
        persons_["john"] = "programmer";
    }

    virtual void SetUp() {
        svr_.get("/hi", [&](httplib::Connection& c) {
            c.response.set_content("Hello World!", "text/plain");
        });
        svr_.get("/", [&](httplib::Connection& c) {
            c.response.set_redirect("/hi");
        });
        svr_.post("/person", [&](httplib::Connection& c) {
            const auto& req = c.request;
            if (req.has_param("name") && req.has_param("note")) {
                persons_[req.params.at("name")] = req.params.at("note");
            } else {
                c.response.status = 400;
            }
        });
        svr_.get("/person/(.*)", [&](httplib::Connection& c) {
            const auto& req = c.request;
            std::string name = req.matches[1];
            if (persons_.find(name) != persons_.end()) {
                auto note = persons_[name];
                c.response.set_content(note, "text/plain");
            } else {
                c.response.status = 404;
            }
        });
        f_ = async([&](){ svr_.run(); });
    }

    virtual void TearDown() {
        svr_.stop();
        f_.get();
    }

    const char* HOST = "localhost";
    const int   PORT = 1914;

    std::map<std::string, std::string> persons_;
    Server                             svr_;
    Client                             cli_;
    std::future<void>                  f_;
};

TEST_F(ServerTest, GetMethod200)
{
    auto res = cli_.get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, GetMethod302)
{
    auto res = cli_.get("/");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(302, res->status);
    EXPECT_EQ("/hi", res->get_header_value("Location"));
}

TEST_F(ServerTest, GetMethod404)
{
    auto res = cli_.get("/invalid");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodPersonJohn)
{
    auto res = cli_.get("/person/john");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("programmer", res->body);
}

TEST_F(ServerTest, PostMethod)
{
    auto res = cli_.get("/person/john3");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(404, res->status);

    res = cli_.post("/person", "name=john3&note=coder", "application/x-www-form-urlencoded");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);

    res = cli_.get("/person/john3");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
    ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
    ASSERT_EQ("coder", res->body);
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
