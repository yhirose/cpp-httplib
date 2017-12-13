
#include <gtest/gtest.h>
#include <httplib.h>
#include <future>
#include <iostream>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"

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
    Params dic;

    detail::split(s.c_str(), s.c_str() + s.size(), '&', [&](const char* b, const char* e) {
        string key, val;
        detail::split(b, e, '=', [&](const char* b, const char* e) {
            if (key.empty()) {
                key.assign(b, e);
            } else {
                val.assign(b, e);
            }
        });
        dic.emplace(key, val);
    });

    EXPECT_EQ("val1", dic.find("key1")->second);
    EXPECT_EQ("val2", dic.find("key2")->second);
    EXPECT_EQ("val3", dic.find("key3")->second);
}

TEST(ParseQueryTest, ParseQueryString)
{
    string s = "key1=val1&key2=val2&key3=val3";
    Params dic;

    detail::parse_query_text(s, dic);

    EXPECT_EQ("val1", dic.find("key1")->second);
    EXPECT_EQ("val2", dic.find("key2")->second);
    EXPECT_EQ("val3", dic.find("key3")->second);
}

TEST(SocketTest, OpenClose)
{
    socket_t sock = detail::create_server_socket(HOST, PORT, 0);
    ASSERT_NE(-1, sock);

    auto ret = detail::close_socket(sock);
    EXPECT_EQ(0, ret);
}

TEST(SocketTest, OpenCloseWithAI_PASSIVE)
{
    socket_t sock = detail::create_server_socket(nullptr, PORT, AI_PASSIVE);
    ASSERT_NE(-1, sock);

    auto ret = detail::close_socket(sock);
    EXPECT_EQ(0, ret);
}

TEST(GetHeaderValueTest, DefaultValue)
{
    Headers headers = {{"Dummy","Dummy"}};
    auto val = detail::get_header_value(headers, "Content-Type", "text/plain");
    EXPECT_STREQ("text/plain", val);
}

TEST(GetHeaderValueTest, DefaultValueInt)
{
    Headers headers = {{"Dummy","Dummy"}};
    auto val = detail::get_header_value_int(headers, "Content-Length", 100);
    EXPECT_EQ(100, val);
}

TEST(GetHeaderValueTest, RegularValue)
{
    Headers headers = {{"Content-Type", "text/html"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value(headers, "Content-Type", "text/plain");
    EXPECT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, RegularValueInt)
{
    Headers headers = {{"Content-Length", "100"}, {"Dummy", "Dummy"}};
    auto val = detail::get_header_value_int(headers, "Content-Length", 0);
    EXPECT_EQ(100, val);
}

TEST(GetHeaderValueTest, Range)
{
    {
        Headers headers = { make_range_header(1) };
        auto val = detail::get_header_value(headers, "Range", 0);
        EXPECT_STREQ("bytes=1-", val);
    }

    {
        Headers headers = { make_range_header(1, 10) };
        auto val = detail::get_header_value(headers, "Range", 0);
        EXPECT_STREQ("bytes=1-10", val);
    }

    {
        Headers headers = { make_range_header(1, 10, 100) };
        auto val = detail::get_header_value(headers, "Range", 0);
        EXPECT_STREQ("bytes=1-10, 100-", val);
    }

    {
        Headers headers = { make_range_header(1, 10, 100, 200) };
        auto val = detail::get_header_value(headers, "Range", 0);
        EXPECT_STREQ("bytes=1-10, 100-200", val);
    }
}

void testChunkedEncoding(httplib::HttpVersion ver)
{
    auto host = "www.httpwatch.com";
    auto port = 80;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    httplib::SSLClient cli(host, port, ver);
#else
    httplib::Client cli(host, port, ver);
#endif

    auto res = cli.get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137");
    ASSERT_TRUE(res != nullptr);

    std::string out;
    httplib::detail::read_file("./image.jpg", out);

    EXPECT_EQ(200, res->status);
    EXPECT_EQ(out, res->body);
}

TEST(ChunkedEncodingTest, FromHTTPWatch)
{
    testChunkedEncoding(httplib::HttpVersion::v1_0);
    testChunkedEncoding(httplib::HttpVersion::v1_1);
}

TEST(RangeTest, FromHTTPBin)
{
    auto host = "httpbin.org";
    auto port = 80;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    httplib::SSLClient cli(host, port, httplib::HttpVersion::v1_1);
#else
    httplib::Client cli(host, port, httplib::HttpVersion::v1_1);
#endif

    {
        httplib::Headers headers;
        auto res = cli.get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
        EXPECT_EQ(200, res->status);
    }

    {
        httplib::Headers headers = { httplib::make_range_header(1) };
        auto res = cli.get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "bcdefghijklmnopqrstuvwxyzabcdef");
        EXPECT_EQ(206, res->status);
    }

    {
        httplib::Headers headers = { httplib::make_range_header(1, 10) };
        auto res = cli.get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "bcdefghijk");
        EXPECT_EQ(206, res->status);
    }
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest()
        : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        , svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
        , up_(false) {}

    virtual void SetUp() {
		svr_.set_base_dir("./www");

        svr_.get("/hi", [&](const Request& /*req*/, Response& res) {
                res.set_content("Hello World!", "text/plain");
            })
            .get("/endwith%", [&](const Request& /*req*/, Response& res) {
                res.set_content("Hello World!", "text/plain");
            })
            .get("/", [&](const Request& /*req*/, Response& res) {
                res.set_redirect("/hi");
            })
            .post("/person", [&](const Request& req, Response& res) {
                if (req.has_param("name") && req.has_param("note")) {
                    persons_[req.get_param_value("name")] = req.get_param_value("note");
                } else {
                    res.status = 400;
                }
            })
            .get("/person/(.*)", [&](const Request& req, Response& res) {
                string name = req.matches[1];
                if (persons_.find(name) != persons_.end()) {
                    auto note = persons_[name];
                    res.set_content(note, "text/plain");
                } else {
                    res.status = 404;
                }
            })
            .post("/multipart", [&](const Request& req, Response& /*res*/) {
                EXPECT_EQ(5u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));

                {
                    const auto& file = req.get_file_value("text1");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("text default", req.body.substr(file.offset, file.length));
                }

                {
                    const auto& file = req.get_file_value("text2");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("aωb", req.body.substr(file.offset, file.length));
                }

                {
                    const auto& file = req.get_file_value("file1");
                    EXPECT_EQ("hello.txt", file.filename);
                    EXPECT_EQ("text/plain", file.content_type);
                    EXPECT_EQ("h\ne\n\nl\nl\no\n", req.body.substr(file.offset, file.length));
                }

                {
                    const auto& file = req.get_file_value("file3");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("application/octet-stream", file.content_type);
                    EXPECT_EQ(0u, file.length);
                }
            })
            .get("/stop", [&](const Request& /*req*/, Response& /*res*/) {
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLClient           cli_;
    SSLServer           svr_;
#else
    Client              cli_;
    Server              svr_;
#endif
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

    Params params;
    params.emplace("name", "john2");
    params.emplace("note", "coder");

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

    auto body = R"(<html>
<head>
</head>
<body>
  <a href="/dir/test.html">Test</a>
  <a href="/hi">hi</a>
</body>
</html>
)";
	EXPECT_EQ(body, res->body);
}

TEST_F(ServerTest, GetMethodDirTest)
{
	auto res = cli_.get("/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirTestWithDoubleDots)
{
	auto res = cli_.get("/dir/../dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidPath)
{
	auto res = cli_.get("/dir/../test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir)
{
	auto res = cli_.get("/../www/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir2)
{
	auto res = cli_.get("/dir/../../www/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidBaseDir)
{
	EXPECT_EQ(false, svr_.set_base_dir("invalid_dir"));
	EXPECT_EQ(true, svr_.set_base_dir("."));
}

TEST_F(ServerTest, EmptyRequest)
{
	auto res = cli_.get("");
	ASSERT_TRUE(res == nullptr);
}

TEST_F(ServerTest, LongRequest)
{
	auto res = cli_.get("/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/__ok__");

	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, TooLongRequest)
{
	auto res = cli_.get("/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/__ng___");

	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, LongHeader)
{
    Request req;
    req.method = "GET";
    req.path = "/hi";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");

	req.headers.emplace("Header-Name", "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, TooLongHeader)
{
    Request req;
    req.method = "GET";
    req.path = "/hi";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");

	req.headers.emplace("Header-Name", "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncoding)
{
    auto res = cli_.get("/e%6edwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncodingUnicode)
{
    auto res = cli_.get("/e%u006edwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, InvalidPercentEncoding)
{
    auto res = cli_.get("/%endwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidPercentEncodingUnicode)
{
    auto res = cli_.get("/%uendwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, MultipartFormData)
{
    Request req;
    req.method = "POST";
    req.path = "/multipart";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");
    req.headers.emplace("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarysBREP3G013oUrLB4");

    req.body = "------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"text1\"\r\n\r\ntext default\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"text2\"\r\n\r\naωb\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nh\ne\n\nl\nl\no\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"file2\"; filename=\"world.json\"\r\nContent-Type: application/json\r\n\r\n{\n  \"world\", true\n}\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"file3\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4--\r\n";

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, CaseInsensitiveHeaderName)
{
    auto res = cli_.get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("content-type"));
    EXPECT_EQ("Hello World!", res->body);
}

class ServerTestWithAI_PASSIVE : public ::testing::Test {
protected:
    ServerTestWithAI_PASSIVE()
        : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        , svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
        , up_(false) {}

    virtual void SetUp() {
        svr_.get("/hi", [&](const Request& /*req*/, Response& res) {
            res.set_content("Hello World!", "text/plain");
        });

        svr_.get("/stop", [&](const Request& /*req*/, Response& /*res*/) {
            svr_.stop();
        });

        f_ = async([&](){
            up_ = true;
            svr_.listen(nullptr, PORT, AI_PASSIVE);
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

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLClient           cli_;
    SSLServer           svr_;
#else
    Client              cli_;
    Server              svr_;
#endif
    future<void>        f_;
    bool                up_;
};

TEST_F(ServerTestWithAI_PASSIVE, GetMethod200)
{
    auto res = cli_.get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("Hello World!", res->body);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(SSLClientTest, ServerNameIndication)
{
    SSLClient cli("httpbin.org", 443);
    auto res = cli.get("/get");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
}
#endif

#ifdef _WIN32
TEST(CleanupTest, WSACleanup)
{
    int ret = WSACleanup();
    ASSERT_EQ(0, ret);
}
#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
