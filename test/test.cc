
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

TEST(ChunkedEncodingTest, FromHTTPWatch)
{
    auto host = "www.httpwatch.com";
    auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    auto res = cli.Get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137");
    ASSERT_TRUE(res != nullptr);

    std::string out;
    httplib::detail::read_file("./image.jpg", out);

    EXPECT_EQ(200, res->status);
    EXPECT_EQ(out, res->body);
}

TEST(RangeTest, FromHTTPBin)
{
    auto host = "httpbin.org";
    auto sec = 5;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    {
        httplib::Headers headers;
        auto res = cli.Get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
        EXPECT_EQ(200, res->status);
    }

    {
        httplib::Headers headers = { httplib::make_range_header(1) };
        auto res = cli.Get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "bcdefghijklmnopqrstuvwxyzabcdef");
        EXPECT_EQ(206, res->status);
    }

    {
        httplib::Headers headers = { httplib::make_range_header(1, 10) };
        auto res = cli.Get("/range/32", headers);
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->body, "bcdefghijk");
        EXPECT_EQ(206, res->status);
    }
}

TEST(ConnectionErrorTest, InvalidHost)
{
    auto host = "abcde.com";
    auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    auto res = cli.Get("/");
    ASSERT_TRUE(res == nullptr);
}

TEST(ConnectionErrorTest, InvalidPort)
{
    auto host = "localhost";
    auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 44380;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 8080;
    httplib::Client cli(host, port, sec);
#endif

    auto res = cli.Get("/");
    ASSERT_TRUE(res == nullptr);
}

TEST(ConnectionErrorTest, Timeout)
{
    auto host = "google.com";
    auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 44380;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 8080;
    httplib::Client cli(host, port, sec);
#endif

    auto res = cli.Get("/");
    ASSERT_TRUE(res == nullptr);
}

TEST(CancelTest, NoCancel) {
    auto host = "httpbin.org";
    auto sec = 5;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    httplib::Headers headers;
    auto res = cli.Get("/range/32", headers, [](uint64_t, uint64_t) {
        return true;
    });
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
    EXPECT_EQ(200, res->status);
}

TEST(CancelTest, WithCancelSmallPayload) {
    auto host = "httpbin.org";
    auto sec = 5;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    httplib::Headers headers;
    auto res = cli.Get("/range/32", headers, [](uint64_t, uint64_t) {
        return false;
    });
    ASSERT_TRUE(res == nullptr);
}

TEST(CancelTest, WithCancelLargePayload) {
    auto host = "httpbin.org";
    auto sec = 5;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto port = 443;
    httplib::SSLClient cli(host, port, sec);
#else
    auto port = 80;
    httplib::Client cli(host, port, sec);
#endif

    uint32_t count = 0;
    httplib::Headers headers;
    auto res = cli.Get("/range/65536", headers, [&count](uint64_t, uint64_t) {
        return (count++ == 0);
    });
    ASSERT_TRUE(res == nullptr);
}

TEST(Server, BindAndListenSeparately) {
    Server svr;
    int port = svr.bind_to_any_port("localhost");
    ASSERT_TRUE(port > 0);
    svr.stop();
}

class ServerTest : public ::testing::Test {
protected:
    ServerTest()
        : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        , svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
        {}

    virtual void SetUp() {
		svr_.set_base_dir("./www");

        svr_.Get("/hi", [&](const Request& /*req*/, Response& res) {
                res.set_content("Hello World!", "text/plain");
            })
            .Get("/slow", [&](const Request& /*req*/, Response& res) {
                msleep(2000);
                res.set_content("slow", "text/plain");
            })
            .Get("/remote_addr", [&](const Request& req, Response& res) {
                auto remote_addr = req.headers.find("REMOTE_ADDR")->second;
                res.set_content(remote_addr.c_str(), "text/plain");
            })
            .Get("/endwith%", [&](const Request& /*req*/, Response& res) {
                res.set_content("Hello World!", "text/plain");
            })
            .Get("/", [&](const Request& /*req*/, Response& res) {
                res.set_redirect("/hi");
            })
            .Post("/person", [&](const Request& req, Response& res) {
                if (req.has_param("name") && req.has_param("note")) {
                    persons_[req.get_param_value("name")] = req.get_param_value("note");
                } else {
                    res.status = 400;
                }
            })
            .Get("/person/(.*)", [&](const Request& req, Response& res) {
                string name = req.matches[1];
                if (persons_.find(name) != persons_.end()) {
                    auto note = persons_[name];
                    res.set_content(note, "text/plain");
                } else {
                    res.status = 404;
                }
            })
            .Get("/streamedchunked", [&](const Request& /*req*/, Response& res) {
                res.streamcb = [] (uint64_t offset) {
                    if (offset < 3)
                        return "a";
                    if (offset < 6)
                        return "b";
                    return "";
                };
            })
            .Get("/streamed", [&](const Request& /*req*/, Response& res) {
                res.set_header("Content-Length", "6");
                res.streamcb = [] (uint64_t offset) {
                    if (offset < 3)
                        return "a";
                    if (offset < 6)
                        return "b";
                    return "";
                };
            })
            .Post("/chunked", [&](const Request& req, Response& /*res*/) {
                EXPECT_EQ(req.body, "dechunked post body");
            })
            .Post("/largechunked", [&](const Request& req, Response& /*res*/) {
                std::string expected(6 * 30 * 1024u, 'a');
                EXPECT_EQ(req.body, expected);
            })
            .Post("/multipart", [&](const Request& req, Response& /*res*/) {
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
            .Put("/put", [&](const Request& req, Response& res) {
                EXPECT_EQ(req.body, "PUT");
                res.set_content(req.body, "text/plain");
            })
            .Delete("/delete", [&](const Request& /*req*/, Response& res) {
                res.set_content("DELETE", "text/plain");
            })
            .Options(R"(\*)", [&](const Request& /*req*/, Response& res) {
                res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
            })
            .Get("/request-target", [&](const Request& req, Response& /*res*/) {
                EXPECT_EQ("/request-target?aaa=bbb&ccc=ddd", req.target);
                EXPECT_EQ("bbb", req.get_param_value("aaa"));
                EXPECT_EQ("ddd", req.get_param_value("ccc"));
            })
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
            .Get("/gzip", [&](const Request& /*req*/, Response& res) {
                res.set_content("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", "text/plain");
            })
            .Get("/nogzip", [&](const Request& /*req*/, Response& res) {
                res.set_content("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", "application/octet-stream");
            })
            .Post("/gzipmultipart", [&](const Request& req, Response& /*res*/) {
                EXPECT_EQ(2u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));

                {
                    const auto& file = req.get_file_value("key1");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("test", req.body.substr(file.offset, file.length));
                }

                {
                    const auto& file = req.get_file_value("key2");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("--abcdefg123", req.body.substr(file.offset, file.length));
                }
            })
#endif
            ;

        persons_["john"] = "programmer";

        t_ = thread([&](){
            ASSERT_TRUE(svr_.listen(HOST, PORT));
        });

        while (!svr_.is_running()) {
            msleep(1);
        }
    }

    virtual void TearDown() {
        svr_.stop();
        for (auto& t: request_threads_) {
            t.join();
        }
        t_.join();
    }

    map<string, string> persons_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLClient           cli_;
    SSLServer           svr_;
#else
    Client              cli_;
    Server              svr_;
#endif
    thread              t_;
    std::vector<thread> request_threads_;
};

TEST_F(ServerTest, GetMethod200)
{
    auto res = cli_.Get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ("HTTP/1.1", res->version);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("close", res->get_header_value("Connection"));
    EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, GetMethod302)
{
    auto res = cli_.Get("/");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(302, res->status);
    EXPECT_EQ("/hi", res->get_header_value("Location"));
}

TEST_F(ServerTest, GetMethod404)
{
    auto res = cli_.Get("/invalid");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, HeadMethod200)
{
    auto res = cli_.Head("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, HeadMethod404)
{
    auto res = cli_.Head("/invalid");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(404, res->status);
    EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, GetMethodPersonJohn)
{
    auto res = cli_.Get("/person/john");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("programmer", res->body);
}

TEST_F(ServerTest, PostMethod1)
{
    auto res = cli_.Get("/person/john1");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(404, res->status);

    res = cli_.Post("/person", "name=john1&note=coder", "application/x-www-form-urlencoded");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);

    res = cli_.Get("/person/john1");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
    ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
    ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PostMethod2)
{
    auto res = cli_.Get("/person/john2");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(404, res->status);

    Params params;
    params.emplace("name", "john2");
    params.emplace("note", "coder");

    res = cli_.Post("/person", params);
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);

    res = cli_.Get("/person/john2");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(200, res->status);
    ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
    ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, GetMethodDir)
{
	auto res = cli_.Get("/dir/");
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
	auto res = cli_.Get("/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirTestWithDoubleDots)
{
	auto res = cli_.Get("/dir/../dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
	EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
	EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidPath)
{
	auto res = cli_.Get("/dir/../test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir)
{
	auto res = cli_.Get("/../www/dir/test.html");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir2)
{
	auto res = cli_.Get("/dir/../../www/dir/test.html");
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
	auto res = cli_.Get("");
	ASSERT_TRUE(res == nullptr);
}

TEST_F(ServerTest, LongRequest)
{
	auto res = cli_.Get("/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/__ok__");

	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, TooLongRequest)
{
	auto res = cli_.Get("/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/TooLongRequest/__ng___");

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
    auto res = cli_.Get("/e%6edwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncodingUnicode)
{
    auto res = cli_.Get("/e%u006edwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, InvalidPercentEncoding)
{
    auto res = cli_.Get("/%endwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidPercentEncodingUnicode)
{
    auto res = cli_.Get("/%uendwith%");
    ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, EndWithPercentCharacterInQuery)
{
    auto res = cli_.Get("/hello?aaa=bbb%");
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

    req.body = "------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"text1\"\r\n\r\ntext default\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"text2\"\r\n\r\naωb\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"hello.txt\"\r\nContent-Type: text/plain\r\n\r\nh\ne\n\nl\nl\no\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\nContent-Disposition: form-data; name=\"file2\"; filename=\"world.json\"\r\nContent-Type: application/json\r\n\r\n{\n  \"world\", true\n}\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4\r\ncontent-disposition: form-data; name=\"file3\"; filename=\"\"\r\ncontent-type: application/octet-stream\r\n\r\n\r\n------WebKitFormBoundarysBREP3G013oUrLB4--\r\n";

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, CaseInsensitiveHeaderName)
{
    auto res = cli_.Get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("content-type"));
    EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, CaseInsensitiveTransferEncoding)
{
    Request req;
    req.method = "POST";
    req.path = "/chunked";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");
    req.headers.emplace("Content-Type", "text/plain");
    req.headers.emplace("Content-Length", "0");
    req.headers.emplace("Transfer-Encoding", "Chunked");  // Note, "Chunked" rather than typical "chunked".

    // Client does not chunk, so make a chunked body manually.
    req.body = "4\r\ndech\r\nf\r\nunked post body\r\n0\r\n\r\n";

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GetStreamed)
{
    auto res = cli_.Get("/streamed");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("6", res->get_header_value("Content-Length"));
    EXPECT_TRUE(res->body == "aaabbb");
}

TEST_F(ServerTest, GetStreamedChunked)
{
    auto res = cli_.Get("/streamedchunked");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_TRUE(res->body == "aaabbb");
}

TEST_F(ServerTest, LargeChunkedPost) {
    Request req;
    req.method = "POST";
    req.path = "/largechunked";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");
    req.headers.emplace("Content-Type", "text/plain");
    req.headers.emplace("Content-Length", "0");
    req.headers.emplace("Transfer-Encoding", "chunked");

    std::string long_string(30 * 1024u, 'a');
    std::string chunk = "7800\r\n" + long_string + "\r\n";

    // Attempt to make a large enough post to exceed OS buffers, to test that
    // the server handles short reads if the full chunk data isn't available.
    req.body = chunk + chunk + chunk + chunk + chunk + chunk + "0\r\n\r\n";

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

	ASSERT_TRUE(ret);
	EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GetMethodRemoteAddr)
{
    auto res = cli_.Get("/remote_addr");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_TRUE(res->body == "::1" || res->body == "127.0.0.1");
}

TEST_F(ServerTest, SlowRequest)
{
    request_threads_.push_back(std::thread([=]() { auto res = cli_.Get("/slow"); }));
    request_threads_.push_back(std::thread([=]() { auto res = cli_.Get("/slow"); }));
    request_threads_.push_back(std::thread([=]() { auto res = cli_.Get("/slow"); }));
    msleep(100);
}

TEST_F(ServerTest, Put)
{
    auto res = cli_.Put("/put", "PUT", "text/plain");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, Delete)
{
    auto res = cli_.Delete("/delete");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("DELETE", res->body);
}

TEST_F(ServerTest, Options)
{
    auto res = cli_.Options("*");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("GET, POST, HEAD, OPTIONS", res->get_header_value("Allow"));
    EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, URL)
{
    auto res = cli_.Get("/request-target?aaa=bbb&ccc=ddd");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, Gzip)
{
    Headers headers;
    headers.emplace("Accept-Encoding", "gzip, deflate");
    auto res = cli_.Get("/gzip", headers);

    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("33", res->get_header_value("Content-Length"));
    EXPECT_EQ("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", res->body);
    EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, NoGzip)
{
    Headers headers;
    headers.emplace("Accept-Encoding", "gzip, deflate");
    auto res = cli_.Get("/nogzip", headers);

    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(false, res->has_header("Content-Encoding"));
    EXPECT_EQ("application/octet-stream", res->get_header_value("Content-Type"));
    EXPECT_EQ("100", res->get_header_value("Content-Length"));
    EXPECT_EQ("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", res->body);
    EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, MultipartFormDataGzip)
{
    Request req;
    req.method = "POST";
    req.path = "/gzipmultipart";

    std::string host_and_port;
    host_and_port += HOST;
    host_and_port += ":";
    host_and_port += std::to_string(PORT);

    req.headers.emplace("Host", host_and_port.c_str());
    req.headers.emplace("Accept", "*/*");
    req.headers.emplace("User-Agent", "cpp-httplib/0.1");
    req.headers.emplace("Content-Type", "multipart/form-data; boundary=------------------------fcba8368a9f48c0f");
    req.headers.emplace("Content-Encoding", "gzip");

    // compressed_body generated by creating input.txt to this file:
    /*
    --------------------------fcba8368a9f48c0f
    Content-Disposition: form-data; name="key1"

    test
    --------------------------fcba8368a9f48c0f
    Content-Disposition: form-data; name="key2"

    --abcdefg123
    --------------------------fcba8368a9f48c0f--
    */
    // then running unix2dos input.txt; gzip -9 -c input.txt | xxd -i.
    uint8_t compressed_body[] = {
        0x1f, 0x8b, 0x08, 0x08, 0x48, 0xf1, 0xd4, 0x5a, 0x02, 0x03, 0x69, 0x6e,
        0x70, 0x75, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00, 0xd3, 0xd5, 0xc5, 0x05,
        0xd2, 0x92, 0x93, 0x12, 0x2d, 0x8c, 0xcd, 0x2c, 0x12, 0x2d, 0xd3, 0x4c,
        0x2c, 0x92, 0x0d, 0xd2, 0x78, 0xb9, 0x9c, 0xf3, 0xf3, 0x4a, 0x52, 0xf3,
        0x4a, 0x74, 0x5d, 0x32, 0x8b, 0x0b, 0xf2, 0x8b, 0x33, 0x4b, 0x32, 0xf3,
        0xf3, 0xac, 0x14, 0xd2, 0xf2, 0x8b, 0x72, 0x75, 0x53, 0x12, 0x4b, 0x12,
        0xad, 0x15, 0xf2, 0x12, 0x73, 0x53, 0x6d, 0x95, 0xb2, 0x53, 0x2b, 0x0d,
        0x95, 0x78, 0xb9, 0x78, 0xb9, 0x4a, 0x52, 0x8b, 0x4b, 0x78, 0xb9, 0x74,
        0x69, 0x61, 0x81, 0x11, 0xd8, 0x02, 0x5d, 0xdd, 0xc4, 0xa4, 0xe4, 0x94,
        0xd4, 0xb4, 0x74, 0x43, 0x23, 0x63, 0x52, 0x2c, 0xd2, 0xd5, 0xe5, 0xe5,
        0x02, 0x00, 0xff, 0x0e, 0x72, 0xdf, 0xf8, 0x00, 0x00, 0x00
    };

    req.body = std::string((char*)compressed_body, sizeof(compressed_body) / sizeof(compressed_body[0]));

    auto res = std::make_shared<Response>();
    auto ret = cli_.send(req, *res);

    ASSERT_TRUE(ret);
    EXPECT_EQ(200, res->status);
}
#endif

class ServerTestWithAI_PASSIVE : public ::testing::Test {
protected:
    ServerTestWithAI_PASSIVE()
        : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        , svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
        {}

    virtual void SetUp() {
        svr_.Get("/hi", [&](const Request& /*req*/, Response& res) {
            res.set_content("Hello World!", "text/plain");
        });

        t_ = thread([&]() {
            ASSERT_TRUE(svr_.listen(nullptr, PORT, AI_PASSIVE));
        });

        while (!svr_.is_running()) {
            msleep(1);
        }
    }

    virtual void TearDown() {
        svr_.stop();
        t_.join();
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLClient           cli_;
    SSLServer           svr_;
#else
    Client              cli_;
    Server              svr_;
#endif
    thread              t_;
};

TEST_F(ServerTestWithAI_PASSIVE, GetMethod200)
{
    auto res = cli_.Get("/hi");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
    EXPECT_EQ("Hello World!", res->body);
}

class ServerUpDownTest : public ::testing::Test {
protected:
    ServerUpDownTest()
        : cli_(HOST, PORT)
        {}

    virtual void SetUp() {
        t_ = thread([&](){
            svr_.bind_to_any_port(HOST);
            msleep(500);
            ASSERT_TRUE(svr_.listen_after_bind());
        });

        while (!svr_.is_running()) {
            msleep(1);
        }
    }

    virtual void TearDown() {
        svr_.stop();
        t_.join();
    }

    Client              cli_;
    Server              svr_;
    thread              t_;
};

TEST_F(ServerUpDownTest, QuickStartStop)
{
    // Should not crash, especially when run with
    // --gtest_filter=ServerUpDownTest.QuickStartStop --gtest_repeat=1000
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(SSLClientTest, ServerNameIndication)
{
    SSLClient cli("httpbin.org", 443);
    auto res = cli.Get("/get");
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
