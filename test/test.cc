
#include <gtest/gtest.h>
#include <httplib.h>
#include <future>
#include <iostream>

#ifdef _WIN32
#include <process.h>
#define msleep(n) ::Sleep(n)
#else
#define msleep(n) ::usleep(n * 1000)
#endif

using namespace std;
using namespace httplib;

const char* HOST = "localhost";
const int   PORT = 1234;

#ifdef _WIN32
TEST(StartupTest, WSAStartup)
{
    WSADATA wsaData;
    int ret = WSAStartup(0x0002, &wsaData);
    ASSERT_EQ(0, ret);
}
#endif

TEST(SplitTest, ParseQueryString)
{
    string s = "key1=val1&key2=val2&key3=val3";
    map<string, string> dic;

    detail::split(s.c_str(), s.c_str() + s.size(), '&', [&](const char* b, const char* e) {
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

    detail::parse_query_text(s, dic);

    EXPECT_EQ("val1", dic["key1"]);
    EXPECT_EQ("val2", dic["key2"]);
    EXPECT_EQ("val3", dic["key3"]);
}

TEST(SocketTest, OpenClose)
{
    socket_t sock = detail::create_server_socket(HOST, PORT);
    ASSERT_NE(-1, sock);

    auto ret = detail::close_socket(sock);
    EXPECT_EQ(0, ret);
}

TEST(GetHeaderValueTest, DefaultValue)
{
    MultiMap map = {{"Dummy","Dummy"}};
    auto val = detail::get_header_value(map, "Content-Type", "text/plain");
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
    MultiMap map = {{"Content-Type", "text/html"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value(map, "Content-Type", "text/plain");
    ASSERT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, RegularValueInt)
{
    MultiMap map = {{"Content-Length", "100"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value_int(map, "Content-Length", 0);
    EXPECT_EQ(100, val);
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest() : cli_(HOST, PORT), up_(false) {
    }

    virtual void SetUp() {
		svr_.set_base_dir("./www");

        svr_.get("/hi", [&](const Request& req, Response& res) {
            res.set_content("Hello World!", "text/plain");
        });

        svr_.get("/", [&](const Request& req, Response& res) {
            res.set_redirect("/hi");
        });

        svr_.post("/person", [&](const Request& req, Response& res) {
            if (req.has_param("name") && req.has_param("note")) {
                persons_[req.params.at("name")] = req.params.at("note");
            } else {
                res.status = 400;
            }
        });

        svr_.get("/person/(.*)", [&](const Request& req, Response& res) {
            string name = req.matches[1];
            if (persons_.find(name) != persons_.end()) {
                auto note = persons_[name];
                res.set_content(note, "text/plain");
            } else {
                res.status = 404;
            }
        });

        svr_.get("/stop", [&](const Request& req, Response& res) {
            svr_.stop();
        });

        persons_["john"] = "programmer";

        f_ = async([&](){
            up_ = true;
            svr_.listen(HOST, PORT);
        });

        while (!up_) {
            msleep(1);
        }
    }

    virtual void TearDown() {
        //svr_.stop(); // NOTE: This causes dead lock on Windows.
        cli_.get("/stop");

        f_.get();
    }

    map<string, string> persons_;
    Server              svr_;
    Client              cli_;
    future<void>        f_;
    bool                up_;
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

TEST_F(ServerTest, HeadMethod200)
{
    auto res = cli_.head("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, HeadMethod404)
{
    auto res = cli_.head("/invalid");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(404, res->status);
    EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, GetMethodPersonJohn)
{
    auto res = cli_.get("/person/john");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("programmer", res->body);
}

TEST_F(ServerTest, PostMethod1)
{
    auto res = cli_.get("/person/john1");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(404, res->status);

    res = cli_.post("/person", "name=john1&note=coder", "application/x-www-form-urlencoded");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);

    res = cli_.get("/person/john1");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
    ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
    ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PostMethod2)
{
    auto res = cli_.get("/person/john2");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(404, res->status);

    Map params;
    params["name"] = "john2";
    params["note"] = "coder";

    res = cli_.post("/person", params);
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);

    res = cli_.get("/person/john2");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
    ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
    ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, GetMethodDir)
{
	auto res = cli_.get("/dir/");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("index.html", res->body);
}

TEST_F(ServerTest, GetMethodDirTest)
{
	auto res = cli_.get("/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, InvalidBaseDir)
{
	EXPECT_EQ(false, svr_.set_base_dir("invalid_dir"));
	EXPECT_EQ(true, svr_.set_base_dir("."));
}

#ifdef _WIN32
TEST(CleanupTest, WSACleanup)
{
    int ret = WSACleanup();
    ASSERT_EQ(0, ret);
}
#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
