#include <future>
#include <gtest/gtest.h>
#include <httplib.h>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"
#define CA_CERT_FILE "./ca-bundle.crt"
#define CLIENT_CA_CERT_FILE "./rootCA.cert.pem"
#define CLIENT_CA_CERT_DIR "."
#define CLIENT_CERT_FILE "./client.cert.pem"
#define CLIENT_PRIVATE_KEY_FILE "./client.key.pem"

#ifdef _WIN32
#include <process.h>
#define msleep(n) ::Sleep(n)
#else
#define msleep(n) ::usleep(n * 1000)
#endif

using namespace std;
using namespace httplib;

const char *HOST = "localhost";
const int PORT = 1234;

const string LONG_QUERY_VALUE = string(25000, '@');
const string LONG_QUERY_URL = "/long-query-value?key=" + LONG_QUERY_VALUE;

const std::string JSON_DATA = "{\"hello\":\"world\"}";

#ifdef _WIN32
TEST(StartupTest, WSAStartup) {
  WSADATA wsaData;
  int ret = WSAStartup(0x0002, &wsaData);
  ASSERT_EQ(0, ret);
}
#endif

TEST(SplitTest, ParseQueryString) {
  string s = "key1=val1&key2=val2&key3=val3";
  Params dic;

  detail::split(s.c_str(), s.c_str() + s.size(), '&',
                [&](const char *b, const char *e) {
                  string key, val;
                  detail::split(b, e, '=', [&](const char *b, const char *e) {
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

TEST(ParseQueryTest, ParseQueryString) {
  string s = "key1=val1&key2=val2&key3=val3";
  Params dic;

  detail::parse_query_text(s, dic);

  EXPECT_EQ("val1", dic.find("key1")->second);
  EXPECT_EQ("val2", dic.find("key2")->second);
  EXPECT_EQ("val3", dic.find("key3")->second);
}

TEST(GetHeaderValueTest, DefaultValue) {
  Headers headers = {{"Dummy", "Dummy"}};
  auto val = detail::get_header_value(headers, "Content-Type", 0, "text/plain");
  EXPECT_STREQ("text/plain", val);
}

TEST(GetHeaderValueTest, DefaultValueInt) {
  Headers headers = {{"Dummy", "Dummy"}};
  auto val = detail::get_header_value_uint64(headers, "Content-Length", 100);
  EXPECT_EQ(100ull, val);
}

TEST(GetHeaderValueTest, RegularValue) {
  Headers headers = {{"Content-Type", "text/html"}, {"Dummy", "Dummy"}};
  auto val = detail::get_header_value(headers, "Content-Type", 0, "text/plain");
  EXPECT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, RegularValueInt) {
  Headers headers = {{"Content-Length", "100"}, {"Dummy", "Dummy"}};
  auto val = detail::get_header_value_uint64(headers, "Content-Length", 0);
  EXPECT_EQ(100ull, val);
}

TEST(GetHeaderValueTest, Range) {
  {
    Headers headers = {make_range_header({{1, -1}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=1-", val);
  }

  {
    Headers headers = {make_range_header({{-1, 1}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=-1", val);
  }

  {
    Headers headers = {make_range_header({{1, 10}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=1-10", val);
  }

  {
    Headers headers = {make_range_header({{1, 10}, {100, -1}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=1-10, 100-", val);
  }

  {
    Headers headers = {make_range_header({{1, 10}, {100, 200}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=1-10, 100-200", val);
  }

  {
    Headers headers = {make_range_header({{0, 0}, {-1, 1}})};
    auto val = detail::get_header_value(headers, "Range", 0, 0);
    EXPECT_STREQ("bytes=0-0, -1", val);
  }
}

TEST(ParseHeaderValueTest, Range) {
  {
    Ranges ranges;
    auto ret = detail::parse_range_header("bytes=1-", ranges);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1u, ranges.size());
    EXPECT_EQ(1u, ranges[0].first);
    EXPECT_EQ(-1, ranges[0].second);
  }

  {
    Ranges ranges;
    auto ret = detail::parse_range_header("bytes=-1", ranges);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1u, ranges.size());
    EXPECT_EQ(-1, ranges[0].first);
    EXPECT_EQ(1u, ranges[0].second);
  }

  {
    Ranges ranges;
    auto ret = detail::parse_range_header("bytes=1-10", ranges);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1u, ranges.size());
    EXPECT_EQ(1u, ranges[0].first);
    EXPECT_EQ(10u, ranges[0].second);
  }

  {
    Ranges ranges;
    auto ret = detail::parse_range_header("bytes=10-1", ranges);
    EXPECT_FALSE(ret);
  }

  {
    Ranges ranges;
    auto ret = detail::parse_range_header("bytes=1-10, 100-", ranges);
    EXPECT_TRUE(ret);
    EXPECT_EQ(2u, ranges.size());
    EXPECT_EQ(1u, ranges[0].first);
    EXPECT_EQ(10u, ranges[0].second);
    EXPECT_EQ(100u, ranges[1].first);
    EXPECT_EQ(-1, ranges[1].second);
  }

  {
    Ranges ranges;
    auto ret =
        detail::parse_range_header("bytes=1-10, 100-200, 300-400", ranges);
    EXPECT_TRUE(ret);
    EXPECT_EQ(3u, ranges.size());
    EXPECT_EQ(1u, ranges[0].first);
    EXPECT_EQ(10u, ranges[0].second);
    EXPECT_EQ(100u, ranges[1].first);
    EXPECT_EQ(200u, ranges[1].second);
    EXPECT_EQ(300u, ranges[2].first);
    EXPECT_EQ(400u, ranges[2].second);
  }
}

TEST(ChunkedEncodingTest, FromHTTPWatch) {
  auto host = "www.httpwatch.com";
  auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port, sec);
#else
  auto port = 80;
  httplib::Client cli(host, port, sec);
#endif

  auto res =
      cli.Get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137");
  ASSERT_TRUE(res != nullptr);

  std::string out;
  httplib::detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, res->body);
}

TEST(ChunkedEncodingTest, WithContentReceiver) {
  auto host = "www.httpwatch.com";
  auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port, sec);
#else
  auto port = 80;
  httplib::Client cli(host, port, sec);
#endif

  std::string body;
  auto res =
      cli.Get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137",
              [&](const char *data, size_t data_length) {
                body.append(data, data_length);
                return true;
              });
  ASSERT_TRUE(res != nullptr);

  std::string out;
  httplib::detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, body);
}

TEST(ChunkedEncodingTest, WithResponseHandlerAndContentReceiver) {
  auto host = "www.httpwatch.com";
  auto sec = 2;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port, sec);
#else
  auto port = 80;
  httplib::Client cli(host, port, sec);
#endif

  std::string body;
  auto res = cli.Get(
      "/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137", Headers(),
      [&](const Response &response) {
        EXPECT_EQ(200, response.status);
        return true;
      },
      [&](const char *data, size_t data_length) {
        body.append(data, data_length);
        return true;
      });
  ASSERT_TRUE(res != nullptr);

  std::string out;
  httplib::detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, body);
}

TEST(RangeTest, FromHTTPBin) {
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
    httplib::Headers headers = {httplib::make_range_header({{1, -1}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body, "bcdefghijklmnopqrstuvwxyzabcdef");
    EXPECT_EQ(206, res->status);
  }

  {
    httplib::Headers headers = {httplib::make_range_header({{1, 10}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body, "bcdefghijk");
    EXPECT_EQ(206, res->status);
  }

  {
    httplib::Headers headers = {httplib::make_range_header({{0, 31}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
    EXPECT_EQ(200, res->status);
  }

  {
    httplib::Headers headers = {httplib::make_range_header({{0, -1}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
    EXPECT_EQ(200, res->status);
  }

  {
    httplib::Headers headers = {httplib::make_range_header({{0, 32}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(416, res->status);
  }
}

TEST(ConnectionErrorTest, InvalidHost) {
  auto host = "-abcde.com";
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

TEST(ConnectionErrorTest, InvalidPort) {
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

TEST(ConnectionErrorTest, Timeout) {
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

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return true; });
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

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return false; });
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
  auto res = cli.Get("/range/65536", headers,
                     [&count](uint64_t, uint64_t) { return (count++ == 0); });
  ASSERT_TRUE(res == nullptr);
}

TEST(BaseAuthTest, FromHTTPWatch) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif

  {
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(401, res->status);
  }

  {
    auto res =
        cli.Get("/basic-auth/hello/world",
                {httplib::make_basic_authentication_header("hello", "world")});
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body,
              "{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n");
    EXPECT_EQ(200, res->status);
  }
}

TEST(AbsoluteRedirectTest, Redirect) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(host);
#else
  httplib::Client cli(host);
#endif

  cli.follow_location(true);
  auto res = cli.Get("/absolute-redirect/3");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST(RedirectTest, Redirect) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(host);
#else
  httplib::Client cli(host);
#endif

  cli.follow_location(true);
  auto res = cli.Get("/redirect/3");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST(RelativeRedirectTest, Redirect) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(host);
#else
  httplib::Client cli(host);
#endif

  cli.follow_location(true);
  auto res = cli.Get("/relative-redirect/3");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST(TooManyRedirectTest, Redirect) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(host);
#else
  httplib::Client cli(host);
#endif

  cli.follow_location(true);
  auto res = cli.Get("/redirect/21");
  ASSERT_TRUE(res == nullptr);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(YahooRedirectTest, Redirect) {
  httplib::Client cli("yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(301, res->status);

  cli.follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest, Redirect) {
  httplib::SSLClient cli("httpbin.org");
  cli.follow_location(true);
  auto res =
      cli.Get("/redirect-to?url=http%3A%2F%2Fwww.google.com&status_code=302");
  ASSERT_TRUE(res != nullptr);
}
#endif

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
        ,
        svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
  {
  }

  virtual void SetUp() {
    svr_.set_base_dir("./www");

    svr_.Get("/hi",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("Hello World!", "text/plain");
             })
        .Get("/slow",
             [&](const Request & /*req*/, Response &res) {
               msleep(2000);
               res.set_content("slow", "text/plain");
             })
        .Get("/remote_addr",
             [&](const Request &req, Response &res) {
               auto remote_addr = req.headers.find("REMOTE_ADDR")->second;
               res.set_content(remote_addr.c_str(), "text/plain");
             })
        .Get("/endwith%",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("Hello World!", "text/plain");
             })
        .Get("/", [&](const Request & /*req*/,
                      Response &res) { res.set_redirect("/hi"); })
        .Post("/person",
              [&](const Request &req, Response &res) {
                if (req.has_param("name") && req.has_param("note")) {
                  persons_[req.get_param_value("name")] =
                      req.get_param_value("note");
                } else {
                  res.status = 400;
                }
              })
        .Get("/person/(.*)",
             [&](const Request &req, Response &res) {
               string name = req.matches[1];
               if (persons_.find(name) != persons_.end()) {
                 auto note = persons_[name];
                 res.set_content(note, "text/plain");
               } else {
                 res.status = 404;
               }
             })
        .Post("/x-www-form-urlencoded-json",
              [&](const Request &req, Response &res) {
                auto json = req.get_param_value("json");
                ASSERT_EQ(JSON_DATA, json);
                res.set_content(json, "appliation/json");
                res.status = 200;
              })
        .Get("/streamed-chunked",
             [&](const Request & /*req*/, Response &res) {
               res.set_chunked_content_provider(
                   [](uint64_t /*offset*/, DataSink sink, Done done) {
                     sink("123", 3);
                     sink("456", 3);
                     sink("789", 3);
                     done();
                   });
             })
        .Get("/streamed",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(
                   6, [](uint64_t offset, uint64_t /*length*/, DataSink sink) {
                     sink(offset < 3 ? "a" : "b", 1);
                   });
             })
        .Get("/streamed-with-range",
             [&](const Request & /*req*/, Response &res) {
               auto data = new std::string("abcdefg");
               res.set_content_provider(
                   data->size(),
                   [data](uint64_t offset, uint64_t length, DataSink sink) {
                     size_t DATA_CHUNK_SIZE = 4;
                     const auto &d = *data;
                     auto out_len =
                         std::min(static_cast<size_t>(length), DATA_CHUNK_SIZE);
                     sink(&d[static_cast<size_t>(offset)], out_len);
                   },
                   [data] { delete data; });
             })
        .Get("/streamed-cancel",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(
                   size_t(-1),
                   [](uint64_t /*offset*/, uint64_t /*length*/, DataSink sink) {
                     std::string data = "data_chunk";
                     sink(data.data(), data.size());
                   });
             })
        .Get("/with-range",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("abcdefg", "text/plain");
             })
        .Post("/chunked",
              [&](const Request &req, Response & /*res*/) {
                EXPECT_EQ(req.body, "dechunked post body");
              })
        .Post("/large-chunked",
              [&](const Request &req, Response & /*res*/) {
                std::string expected(6 * 30 * 1024u, 'a');
                EXPECT_EQ(req.body, expected);
              })
        .Post("/multipart",
              [&](const Request &req, Response & /*res*/) {
                EXPECT_EQ(5u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));

                {
                  const auto &file = req.get_file_value("text1");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("text default",
                            req.body.substr(file.offset, file.length));
                }

                {
                  const auto &file = req.get_file_value("text2");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("aωb", req.body.substr(file.offset, file.length));
                }

                {
                  const auto &file = req.get_file_value("file1");
                  EXPECT_EQ("hello.txt", file.filename);
                  EXPECT_EQ("text/plain", file.content_type);
                  EXPECT_EQ("h\ne\n\nl\nl\no\n",
                            req.body.substr(file.offset, file.length));
                }

                {
                  const auto &file = req.get_file_value("file3");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("application/octet-stream", file.content_type);
                  EXPECT_EQ(0u, file.length);
                }
              })
        .Post("/empty",
              [&](const Request &req, Response &res) {
                EXPECT_EQ(req.body, "");
                res.set_content("empty", "text/plain");
              })
        .Put("/put",
             [&](const Request &req, Response &res) {
               EXPECT_EQ(req.body, "PUT");
               res.set_content(req.body, "text/plain");
             })
        .Patch("/patch",
               [&](const Request &req, Response &res) {
                 EXPECT_EQ(req.body, "PATCH");
                 res.set_content(req.body, "text/plain");
               })
        .Delete("/delete",
                [&](const Request & /*req*/, Response &res) {
                  res.set_content("DELETE", "text/plain");
                })
        .Options(R"(\*)",
                 [&](const Request & /*req*/, Response &res) {
                   res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
                 })
        .Get("/request-target",
             [&](const Request &req, Response & /*res*/) {
               EXPECT_EQ("/request-target?aaa=bbb&ccc=ddd", req.target);
               EXPECT_EQ("bbb", req.get_param_value("aaa"));
               EXPECT_EQ("ddd", req.get_param_value("ccc"));
             })
        .Get("/long-query-value",
             [&](const Request &req, Response & /*res*/) {
               EXPECT_EQ(LONG_QUERY_URL, req.target);
               EXPECT_EQ(LONG_QUERY_VALUE, req.get_param_value("key"));
             })
        .Get("/array-param",
             [&](const Request &req, Response & /*res*/) {
               EXPECT_EQ(3u, req.get_param_value_count("array"));
               EXPECT_EQ("value1", req.get_param_value("array", 0));
               EXPECT_EQ("value2", req.get_param_value("array", 1));
               EXPECT_EQ("value3", req.get_param_value("array", 2));
             })
        .Post("/validate-no-multiple-headers",
              [&](const Request &req, Response & /*res*/) {
                EXPECT_EQ(1u, req.get_header_value_count("Content-Length"));
                EXPECT_EQ("5", req.get_header_value("Content-Length"));
              })
        .Post("/content_receiver",
              [&](const Request & /*req*/, Response &res,
                  const ContentReader &content_reader) {
                std::string body;
                content_reader([&](const char *data, size_t data_length) {
                  EXPECT_EQ(data_length, 7);
                  body.append(data, data_length);
                  return true;
                });
                EXPECT_EQ(body, "content");
                res.set_content(body, "text/plain");
              })
        .Put("/content_receiver",
             [&](const Request & /*req*/, Response &res,
                 const ContentReader &content_reader) {
               std::string body;
               content_reader([&](const char *data, size_t data_length) {
                 body.append(data, data_length);
                 return true;
               });
               EXPECT_EQ(body, "content");
               res.set_content(body, "text/plain");
             })
        .Patch("/content_receiver",
               [&](const Request & /*req*/, Response &res,
                   const ContentReader &content_reader) {
                 std::string body;
                 content_reader([&](const char *data, size_t data_length) {
                   body.append(data, data_length);
                   return true;
                 });
                 EXPECT_EQ(body, "content");
                 res.set_content(body, "text/plain");
               })
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
        .Get("/gzip",
             [&](const Request & /*req*/, Response &res) {
               res.set_content(
                   "12345678901234567890123456789012345678901234567890123456789"
                   "01234567890123456789012345678901234567890",
                   "text/plain");
             })
        .Get("/nogzip",
             [&](const Request & /*req*/, Response &res) {
               res.set_content(
                   "12345678901234567890123456789012345678901234567890123456789"
                   "01234567890123456789012345678901234567890",
                   "application/octet-stream");
             })
        .Post("/gzipmultipart",
              [&](const Request &req, Response & /*res*/) {
                EXPECT_EQ(2u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));

                {
                  const auto &file = req.get_file_value("key1");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("test", req.body.substr(file.offset, file.length));
                }

                {
                  const auto &file = req.get_file_value("key2");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("--abcdefg123",
                            req.body.substr(file.offset, file.length));
                }
              })
#endif
        ;

    persons_["john"] = "programmer";

    t_ = thread([&]() { ASSERT_TRUE(svr_.listen(HOST, PORT)); });

    while (!svr_.is_running()) {
      msleep(1);
    }
  }

  virtual void TearDown() {
    svr_.stop();
    for (auto &t : request_threads_) {
      t.join();
    }
    t_.join();
  }

  map<string, string> persons_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli_;
  SSLServer svr_;
#else
  Client cli_;
  Server svr_;
#endif
  thread t_;
  std::vector<thread> request_threads_;
};

TEST_F(ServerTest, GetMethod200) {
  auto res = cli_.Get("/hi");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ("HTTP/1.1", res->version);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ(1, res->get_header_value_count("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, GetMethod302) {
  auto res = cli_.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(302, res->status);
  EXPECT_EQ("/hi", res->get_header_value("Location"));
}

TEST_F(ServerTest, GetMethod404) {
  auto res = cli_.Get("/invalid");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, HeadMethod200) {
  auto res = cli_.Head("/hi");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, HeadMethod404) {
  auto res = cli_.Head("/invalid");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
  EXPECT_EQ("", res->body);
}

TEST_F(ServerTest, GetMethodPersonJohn) {
  auto res = cli_.Get("/person/john");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("programmer", res->body);
}

TEST_F(ServerTest, PostMethod1) {
  auto res = cli_.Get("/person/john1");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(404, res->status);

  res = cli_.Post("/person", "name=john1&note=coder",
                  "application/x-www-form-urlencoded");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);

  res = cli_.Get("/person/john1");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
  ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PostMethod2) {
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

TEST_F(ServerTest, PostWwwFormUrlEncodedJson) {
  Params params;
  params.emplace("json", JSON_DATA);

  auto res = cli_.Post("/x-www-form-urlencoded-json", params);

  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(JSON_DATA, res->body);
}

TEST_F(ServerTest, PostEmptyContent) {
  auto res = cli_.Post("/empty", "", "text/plain");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("empty", res->body);
}

TEST_F(ServerTest, GetMethodDir) {
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

TEST_F(ServerTest, GetMethodDirTest) {
  auto res = cli_.Get("/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirTestWithDoubleDots) {
  auto res = cli_.Get("/dir/../dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidPath) {
  auto res = cli_.Get("/dir/../test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir) {
  auto res = cli_.Get("/../www/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir2) {
  auto res = cli_.Get("/dir/../../www/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidBaseDir) {
  EXPECT_EQ(false, svr_.set_base_dir("invalid_dir"));
  EXPECT_EQ(true, svr_.set_base_dir("."));
}

TEST_F(ServerTest, EmptyRequest) {
  auto res = cli_.Get("");
  ASSERT_TRUE(res == nullptr);
}

TEST_F(ServerTest, LongRequest) {
  std::string request;
  for (size_t i = 0; i < 545; i++) {
    request += "/TooLongRequest";
  }
  request += "OK";

  auto res = cli_.Get(request.c_str());

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, TooLongRequest) {
  std::string request;
  for (size_t i = 0; i < 545; i++) {
    request += "/TooLongRequest";
  }
  request += "_NG";

  auto res = cli_.Get(request.c_str());

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(414, res->status);
}

TEST_F(ServerTest, LongHeader) {
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

  req.headers.emplace(
      "Header-Name",
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@");

  auto res = std::make_shared<Response>();
  auto ret = cli_.send(req, *res);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, LongQueryValue) {
  auto res = cli_.Get(LONG_QUERY_URL.c_str());

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(414, res->status);
}

TEST_F(ServerTest, TooLongHeader) {
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

  req.headers.emplace(
      "Header-Name",
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      "@@@@@@@@@@@@@@@@@");

  auto res = std::make_shared<Response>();
  auto ret = cli_.send(req, *res);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncoding) {
  auto res = cli_.Get("/e%6edwith%");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncodingUnicode) {
  auto res = cli_.Get("/e%u006edwith%");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, InvalidPercentEncoding) {
  auto res = cli_.Get("/%endwith%");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidPercentEncodingUnicode) {
  auto res = cli_.Get("/%uendwith%");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, EndWithPercentCharacterInQuery) {
  auto res = cli_.Get("/hello?aaa=bbb%");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, MultipartFormData) {
  MultipartFormDataItems items = {
      {"text1", "text default", "", ""},
      {"text2", "aωb", "", ""},
      {"file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain"},
      {"file2", "{\n  \"world\", true\n}\n", "world.json", "application/json"},
      {"file3", "", "", "application/octet-stream"},
  };

  auto res = cli_.Post("/multipart", items);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, CaseInsensitiveHeaderName) {
  auto res = cli_.Get("/hi");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("content-type"));
  EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, CaseInsensitiveTransferEncoding) {
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
  req.headers.emplace(
      "Transfer-Encoding",
      "Chunked"); // Note, "Chunked" rather than typical "chunked".

  // Client does not chunk, so make a chunked body manually.
  req.body = "4\r\ndech\r\nf\r\nunked post body\r\n0\r\n\r\n";

  auto res = std::make_shared<Response>();
  auto ret = cli_.send(req, *res);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GetStreamed2) {
  auto res = cli_.Get("/streamed", {{make_range_header({{2, 3}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("2", res->get_header_value("Content-Length"));
  EXPECT_EQ(std::string("ab"), res->body);
}

TEST_F(ServerTest, GetStreamed) {
  auto res = cli_.Get("/streamed");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(std::string("aaabbb"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRange1) {
  auto res = cli_.Get("/streamed-with-range", {{make_range_header({{3, 5}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("3", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("def"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRange2) {
  auto res = cli_.Get("/streamed-with-range", {{make_range_header({{1, -1}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("bcdefg"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRangeMultipart) {
  auto res =
      cli_.Get("/streamed-with-range", {{make_range_header({{1, 2}, {4, 5}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("269", res->get_header_value("Content-Length"));
  EXPECT_EQ(false, res->has_header("Content-Range"));
  EXPECT_EQ(269, res->body.size());
}

TEST_F(ServerTest, GetStreamedEndless) {
  size_t offset = 0;
  auto res = cli_.Get("/streamed-cancel",
                      [&](const char * /*data*/, uint64_t data_length) {
                        if (offset < 100) {
                          offset += data_length;
                          return true;
                        }
                        return false;
                      });
  ASSERT_TRUE(res == nullptr);
}

TEST_F(ServerTest, GetWithRange1) {
  auto res = cli_.Get("/with-range", {{make_range_header({{3, 5}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("3", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("def"), res->body);
}

TEST_F(ServerTest, GetWithRange2) {
  auto res = cli_.Get("/with-range", {{make_range_header({{1, -1}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("bcdefg"), res->body);
}

TEST_F(ServerTest, GetWithRange3) {
  auto res = cli_.Get("/with-range", {{make_range_header({{0, 0}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("1", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("a"), res->body);
}

TEST_F(ServerTest, GetWithRange4) {
  auto res = cli_.Get("/with-range", {{make_range_header({{-1, 2}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("2", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("fg"), res->body);
}

TEST_F(ServerTest, GetWithRangeMultipart) {
  auto res = cli_.Get("/with-range", {{make_range_header({{1, 2}, {4, 5}})}});
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("269", res->get_header_value("Content-Length"));
  EXPECT_EQ(false, res->has_header("Content-Range"));
  EXPECT_EQ(269, res->body.size());
}

TEST_F(ServerTest, GetStreamedChunked) {
  auto res = cli_.Get("/streamed-chunked");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}

TEST_F(ServerTest, LargeChunkedPost) {
  Request req;
  req.method = "POST";
  req.path = "/large-chunked";

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

TEST_F(ServerTest, GetMethodRemoteAddr) {
  auto res = cli_.Get("/remote_addr");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_TRUE(res->body == "::1" || res->body == "127.0.0.1");
}

TEST_F(ServerTest, SlowRequest) {
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
  msleep(100);
}

TEST_F(ServerTest, Put) {
  auto res = cli_.Put("/put", "PUT", "text/plain");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PutWithContentProvider) {
  auto res = cli_.Put(
      "/put", 3,
      [](size_t /*offset*/, size_t /*length*/, DataSink sink) {
        sink("PUT", 3);
      },
      "text/plain");

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, PutWithContentProviderWithGzip) {
  auto res = cli_.Put(
      "/put", 3,
      [](size_t /*offset*/, size_t /*length*/, DataSink sink) {
        sink("PUT", 3);
      },
      "text/plain", true);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}
#endif

TEST_F(ServerTest, Patch) {
  auto res = cli_.Patch("/patch", "PATCH", "text/plain");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PATCH", res->body);
}

TEST_F(ServerTest, Delete) {
  auto res = cli_.Delete("/delete");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("DELETE", res->body);
}

TEST_F(ServerTest, Options) {
  auto res = cli_.Options("*");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("GET, POST, HEAD, OPTIONS", res->get_header_value("Allow"));
  EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, URL) {
  auto res = cli_.Get("/request-target?aaa=bbb&ccc=ddd");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, ArrayParam) {
  auto res = cli_.Get("/array-param?array=value1&array=value2&array=value3");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, NoMultipleHeaders) {
  Headers headers = {{"Content-Length", "5"}};
  auto res = cli_.Post("/validate-no-multiple-headers", headers, "hello",
                       "text/plain");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PostContentReceiver) {
  auto res = cli_.Post("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PostContentReceiverGzip) {
  auto res = cli_.Post("/content_receiver", "content", "text/plain", true);
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PutContentReceiver) {
  auto res = cli_.Put("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PatchContentReceiver) {
  auto res = cli_.Patch("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, HTTP2Magic) {
  Request req;
  req.method = "PRI";
  req.path = "*";
  req.body = "SM";

  auto res = std::make_shared<Response>();
  auto ret = cli_.send(req, *res);

  ASSERT_TRUE(ret);
  EXPECT_EQ(400, res->status);
}
TEST_F(ServerTest, KeepAlive) {
  cli_.set_keep_alive_max_count(4);

  std::vector<Request> requests;
  Get(requests, "/hi");
  Get(requests, "/hi");
  Get(requests, "/hi");
  Get(requests, "/not-exist");
  Post(requests, "/empty", "", "text/plain");

  std::vector<Response> responses;
  auto ret = cli_.send(requests, responses);

  ASSERT_TRUE(ret == true);
  ASSERT_TRUE(requests.size() == responses.size());

  for (int i = 0; i < 3; i++) {
    auto &res = responses[i];
    EXPECT_EQ(200, res.status);
    EXPECT_EQ("text/plain", res.get_header_value("Content-Type"));
    EXPECT_EQ("Hello World!", res.body);
  }

  {
    auto &res = responses[3];
    EXPECT_EQ(404, res.status);
  }

  {
    auto &res = responses[4];
    EXPECT_EQ(200, res.status);
    EXPECT_EQ("text/plain", res.get_header_value("Content-Type"));
    EXPECT_EQ("empty", res.body);
  }
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, Gzip) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");
  auto res = cli_.Get("/gzip", headers);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("33", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            res->body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithoutAcceptEncoding) {
  Headers headers;
  auto res = cli_.Get("/gzip", headers);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ("", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("100", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            res->body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithContentReceiver) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");
  std::string body;
  auto res =
      cli_.Get("/gzip", headers, [&](const char *data, uint64_t data_length) {
        EXPECT_EQ(data_length, 100);
        body.append(data, data_length);
        return true;
      });

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("33", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithContentReceiverWithoutAcceptEncoding) {
  Headers headers;
  std::string body;
  auto res =
      cli_.Get("/gzip", headers, [&](const char *data, uint64_t data_length) {
        EXPECT_EQ(data_length, 100);
        body.append(data, data_length);
        return true;
      });

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ("", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("100", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, NoGzip) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");
  auto res = cli_.Get("/nogzip", headers);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(false, res->has_header("Content-Encoding"));
  EXPECT_EQ("application/octet-stream", res->get_header_value("Content-Type"));
  EXPECT_EQ("100", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            res->body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, NoGzipWithContentReceiver) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");
  std::string body;
  auto res =
      cli_.Get("/nogzip", headers, [&](const char *data, uint64_t data_length) {
        EXPECT_EQ(data_length, 100);
        body.append(data, data_length);
        return true;
      });

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(false, res->has_header("Content-Encoding"));
  EXPECT_EQ("application/octet-stream", res->get_header_value("Content-Type"));
  EXPECT_EQ("100", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, MultipartFormDataGzip) {
  MultipartFormDataItems items = {
      {"key1", "test", "", ""},
      {"key2", "--abcdefg123", "", ""},
  };

  auto res = cli_.Post("/gzipmultipart", items, true);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}
#endif

class ServerTestWithAI_PASSIVE : public ::testing::Test {
protected:
  ServerTestWithAI_PASSIVE()
      : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        ,
        svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
  {
  }

  virtual void SetUp() {
    svr_.Get("/hi", [&](const Request & /*req*/, Response &res) {
      res.set_content("Hello World!", "text/plain");
    });

    t_ = thread([&]() { ASSERT_TRUE(svr_.listen(nullptr, PORT, AI_PASSIVE)); });

    while (!svr_.is_running()) {
      msleep(1);
    }
  }

  virtual void TearDown() {
    svr_.stop();
    t_.join();
  }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli_;
  SSLServer svr_;
#else
  Client cli_;
  Server svr_;
#endif
  thread t_;
};

TEST_F(ServerTestWithAI_PASSIVE, GetMethod200) {
  auto res = cli_.Get("/hi");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);
}

class ServerUpDownTest : public ::testing::Test {
protected:
  ServerUpDownTest() : cli_(HOST, PORT) {}

  virtual void SetUp() {
    t_ = thread([&]() {
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

  Client cli_;
  Server svr_;
  thread t_;
};

TEST_F(ServerUpDownTest, QuickStartStop) {
  // Should not crash, especially when run with
  // --gtest_filter=ServerUpDownTest.QuickStartStop --gtest_repeat=1000
}

class PayloadMaxLengthTest : public ::testing::Test {
protected:
  PayloadMaxLengthTest()
      : cli_(HOST, PORT)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        ,
        svr_(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE)
#endif
  {
  }

  virtual void SetUp() {
    svr_.set_payload_max_length(8);

    svr_.Post("/test", [&](const Request & /*req*/, Response &res) {
      res.set_content("test", "text/plain");
    });

    t_ = thread([&]() { ASSERT_TRUE(svr_.listen(HOST, PORT)); });

    while (!svr_.is_running()) {
      msleep(1);
    }
  }

  virtual void TearDown() {
    svr_.stop();
    t_.join();
  }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli_;
  SSLServer svr_;
#else
  Client cli_;
  Server svr_;
#endif
  thread t_;
};

TEST_F(PayloadMaxLengthTest, ExceedLimit) {
  auto res = cli_.Post("/test", "123456789", "text/plain");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(413, res->status);

  res = cli_.Post("/test", "12345678", "text/plain");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(SSLClientTest, ServerNameIndication) {
  SSLClient cli("httpbin.org", 443);
  auto res = cli.Get("/get");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
}

TEST(SSLClientTest, ServerCertificateVerification) {
  SSLClient cli("google.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(301, res->status);

  cli.enable_server_certificate_verification(true);
  res = cli.Get("/");
  ASSERT_TRUE(res == nullptr);

  cli.set_ca_cert_path(CA_CERT_FILE);
  res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(301, res->status);
}

TEST(SSLClientTest, WildcardHostNameMatch) {
  SSLClient cli("www.youtube.com");

  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.enable_server_certificate_verification(true);

  auto res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
}

TEST(SSLClientServerTest, ClientCertPresent) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE,
                CLIENT_CA_CERT_DIR);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &req, Response &res) {
    res.set_content("test", "text/plain");
    svr.stop();
    ASSERT_TRUE(true);

    auto peer_cert = SSL_get_peer_certificate(req.ssl);
    ASSERT_TRUE(peer_cert != nullptr);

    auto subject_name = X509_get_subject_name(peer_cert);
    ASSERT_TRUE(subject_name != nullptr);

    std::string common_name;
    {
      char name[BUFSIZ];
      auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
                                                name, sizeof(name));
      common_name.assign(name, name_len);
    }

    EXPECT_EQ("Common Name", common_name);

    X509_free(peer_cert);
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  msleep(1);

  httplib::SSLClient cli(HOST, PORT, 30, CLIENT_CERT_FILE,
                         CLIENT_PRIVATE_KEY_FILE);
  auto res = cli.Get("/test");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);

  t.join();
}

TEST(SSLClientServerTest, ClientCertMissing) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE,
                CLIENT_CA_CERT_DIR);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &, Response &) { ASSERT_TRUE(false); });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  msleep(1);

  httplib::SSLClient cli(HOST, PORT, 30);
  auto res = cli.Get("/test");
  ASSERT_TRUE(res == nullptr);

  svr.stop();

  t.join();
}

TEST(SSLClientServerTest, TrustDirOptional) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &, Response &res) {
    res.set_content("test", "text/plain");
    svr.stop();
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  msleep(1);

  httplib::SSLClient cli(HOST, PORT, 30, CLIENT_CERT_FILE,
                         CLIENT_PRIVATE_KEY_FILE);
  auto res = cli.Get("/test");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);

  t.join();
}

/* Cannot test this case as there is no external access to SSL object to check
SSL_get_peer_certificate() == NULL TEST(SSLClientServerTest,
ClientCAPathRequired) { SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE,
nullptr, CLIENT_CA_CERT_DIR);
}
*/
#endif

#ifdef _WIN32
TEST(CleanupTest, WSACleanup) {
  int ret = WSACleanup();
  ASSERT_EQ(0, ret);
}
#endif
