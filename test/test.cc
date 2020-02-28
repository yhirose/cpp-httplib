#include <httplib.h>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <thread>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"
#define CA_CERT_FILE "./ca-bundle.crt"
#define CLIENT_CA_CERT_FILE "./rootCA.cert.pem"
#define CLIENT_CA_CERT_DIR "."
#define CLIENT_CERT_FILE "./client.cert.pem"
#define CLIENT_PRIVATE_KEY_FILE "./client.key.pem"

using namespace std;
using namespace httplib;

const char *HOST = "localhost";
const int PORT = 1234;

const string LONG_QUERY_VALUE = string(25000, '@');
const string LONG_QUERY_URL = "/long-query-value?key=" + LONG_QUERY_VALUE;

const std::string JSON_DATA = "{\"hello\":\"world\"}";

const string LARGE_DATA = string(1024 * 1024 * 100, '@'); // 100MB

MultipartFormData &get_file_value(MultipartFormDataItems &files,
                                  const char *key) {
  auto it = std::find_if(
      files.begin(), files.end(),
      [&](const MultipartFormData &file) { return file.name == key; });
  if (it != files.end()) { return *it; }
  throw std::runtime_error("invalid mulitpart form data name error");
}

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

TEST(ParamsToQueryTest, ConvertParamsToQuery) {
    Params dic;

    EXPECT_EQ(detail::params_to_query_str(dic), "");

    dic.emplace("key1", "val1");

    EXPECT_EQ(detail::params_to_query_str(dic), "key1=val1");

    dic.emplace("key2", "val2");
    dic.emplace("key3", "val3");

    EXPECT_EQ(detail::params_to_query_str(dic), "key1=val1&key2=val2&key3=val3");
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

TEST(BufferStreamTest, read) {
  detail::BufferStream strm1;
  Stream &strm = strm1;

  EXPECT_EQ(5, strm.write("hello"));

  char buf[512];
  EXPECT_EQ(2, strm.read(buf, 2));
  EXPECT_EQ('h', buf[0]);
  EXPECT_EQ('e', buf[1]);

  EXPECT_EQ(2, strm.read(buf, 2));
  EXPECT_EQ('l', buf[0]);
  EXPECT_EQ('l', buf[1]);

  EXPECT_EQ(1, strm.read(buf, 1));
  EXPECT_EQ('o', buf[0]);

  EXPECT_EQ(0, strm.read(buf, 1));
}

TEST(ChunkedEncodingTest, FromHTTPWatch) {
  auto host = "www.httpwatch.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

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

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

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

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

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

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(5);

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

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

  auto res = cli.Get("/");
  ASSERT_TRUE(res == nullptr);
}

TEST(ConnectionErrorTest, InvalidPort) {
  auto host = "localhost";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 44380;
  httplib::SSLClient cli(host, port);
#else
  auto port = 8080;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

  auto res = cli.Get("/");
  ASSERT_TRUE(res == nullptr);
}

TEST(ConnectionErrorTest, Timeout) {
  auto host = "google.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 44380;
  httplib::SSLClient cli(host, port);
#else
  auto port = 8080;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(2);

  auto res = cli.Get("/");
  ASSERT_TRUE(res == nullptr);
}

TEST(CancelTest, NoCancel) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(5);

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return true; });
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(res->body, "abcdefghijklmnopqrstuvwxyzabcdef");
  EXPECT_EQ(200, res->status);
}

TEST(CancelTest, WithCancelSmallPayload) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return false; });
  cli.set_timeout_sec(5);
  ASSERT_TRUE(res == nullptr);
}

TEST(CancelTest, WithCancelLargePayload) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  httplib::SSLClient cli(host, port);
#else
  auto port = 80;
  httplib::Client cli(host, port);
#endif
  cli.set_timeout_sec(5);

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

  {
    cli.set_basic_auth("hello", "world");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->body,
              "{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n");
    EXPECT_EQ(200, res->status);
  }

  {
    cli.set_basic_auth("hello", "bad");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(401, res->status);
  }

  {
    cli.set_basic_auth("bad", "world");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(401, res->status);
  }
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(DigestAuthTest, FromHTTPWatch) {
  auto host = "httpbin.org";
  auto port = 443;
  httplib::SSLClient cli(host, port);

  {
    auto res = cli.Get("/digest-auth/auth/hello/world");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(401, res->status);
  }

  {
    std::vector<std::string> paths = {
        "/digest-auth/auth/hello/world/MD5",
        "/digest-auth/auth/hello/world/SHA-256",
        "/digest-auth/auth/hello/world/SHA-512",
        "/digest-auth/auth-int/hello/world/MD5",
    };

    cli.set_digest_auth("hello", "world");
    for (auto path : paths) {
      auto res = cli.Get(path.c_str());
      ASSERT_TRUE(res != nullptr);
      EXPECT_EQ(res->body,
                "{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n");
      EXPECT_EQ(200, res->status);
    }

    cli.set_digest_auth("hello", "bad");
    for (auto path : paths) {
      auto res = cli.Get(path.c_str());
      ASSERT_TRUE(res != nullptr);
      EXPECT_EQ(400, res->status);
    }

    cli.set_digest_auth("bad", "world");
    for (auto path : paths) {
      auto res = cli.Get(path.c_str());
      ASSERT_TRUE(res != nullptr);
      EXPECT_EQ(400, res->status);
    }
  }
}
#endif

TEST(AbsoluteRedirectTest, Redirect) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(host);
#else
  httplib::Client cli(host);
#endif

  cli.set_follow_location(true);
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

  cli.set_follow_location(true);
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

  cli.set_follow_location(true);
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

  cli.set_follow_location(true);
  auto res = cli.Get("/redirect/21");
  ASSERT_TRUE(res == nullptr);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(YahooRedirectTest, Redirect) {
  httplib::Client cli("yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(301, res->status);

  cli.set_follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest, Redirect) {
  httplib::SSLClient cli("httpbin.org");
  cli.set_follow_location(true);
  auto res =
      cli.Get("/redirect-to?url=http%3A%2F%2Fwww.google.com&status_code=302");
  ASSERT_TRUE(res != nullptr);
}
#endif

TEST(Server, BindAndListenSeparately) {
  Server svr;
  int port = svr.bind_to_any_port("0.0.0.0");
  ASSERT_TRUE(svr.is_valid());
  ASSERT_TRUE(port > 0);
  svr.stop();
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(SSLServer, BindAndListenSeparately) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE, CLIENT_CA_CERT_DIR);
  int port = svr.bind_to_any_port("0.0.0.0");
  ASSERT_TRUE(svr.is_valid());
  ASSERT_TRUE(port > 0);
  svr.stop();
}
#endif

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
    svr_.set_mount_point("/", "./www");
    svr_.set_mount_point("/mount", "./www2");
    svr_.set_file_extension_and_mimetype_mapping("abcde", "text/abcde");

    svr_.Get("/hi",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("Hello World!", "text/plain");
             })
        .Get("/slow",
             [&](const Request & /*req*/, Response &res) {
               std::this_thread::sleep_for(std::chrono::seconds(2));
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
        .Put("/person",
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
                   [](uint64_t /*offset*/, DataSink &sink) {
                     ASSERT_TRUE(sink.is_writable());
                     sink.write("123", 3);
                     sink.write("456", 3);
                     sink.write("789", 3);
                     sink.done();
                   });
             })
        .Get("/streamed-chunked2",
             [&](const Request & /*req*/, Response &res) {
               auto i = new int(0);
               res.set_chunked_content_provider(
                   [i](uint64_t /*offset*/, DataSink &sink) {
                     ASSERT_TRUE(sink.is_writable());
                     switch (*i) {
                     case 0: sink.write("123", 3); break;
                     case 1: sink.write("456", 3); break;
                     case 2: sink.write("789", 3); break;
                     case 3: sink.done(); break;
                     }
                     (*i)++;
                   },
                   [i] { delete i; });
             })
        .Get("/streamed",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(
                   6, [](uint64_t offset, uint64_t /*length*/, DataSink &sink) {
                     sink.write(offset < 3 ? "a" : "b", 1);
                   });
             })
        .Get("/streamed-with-range",
             [&](const Request & /*req*/, Response &res) {
               auto data = new std::string("abcdefg");
               res.set_content_provider(
                   data->size(),
                   [data](uint64_t offset, uint64_t length, DataSink &sink) {
                     ASSERT_TRUE(sink.is_writable());
                     size_t DATA_CHUNK_SIZE = 4;
                     const auto &d = *data;
                     auto out_len =
                         std::min(static_cast<size_t>(length), DATA_CHUNK_SIZE);
                     sink.write(&d[static_cast<size_t>(offset)], out_len);
                   },
                   [data] { delete data; });
             })
        .Get("/streamed-cancel",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(size_t(-1), [](uint64_t /*offset*/,
                                                       uint64_t /*length*/,
                                                       DataSink &sink) {
                 ASSERT_TRUE(sink.is_writable());
                 std::string data = "data_chunk";
                 sink.write(data.data(), data.size());
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
                ASSERT_TRUE(req.body.empty());

                {
                  const auto &file = req.get_file_value("text1");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("text default", file.content);
                }

                {
                  const auto &file = req.get_file_value("text2");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("aωb", file.content);
                }

                {
                  const auto &file = req.get_file_value("file1");
                  EXPECT_EQ("hello.txt", file.filename);
                  EXPECT_EQ("text/plain", file.content_type);
                  EXPECT_EQ("h\ne\n\nl\nl\no\n", file.content);
                }

                {
                  const auto &file = req.get_file_value("file3");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("application/octet-stream", file.content_type);
                  EXPECT_EQ(0u, file.content.size());
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
        .Put("/put-large",
             [&](const Request &req, Response &res) {
               EXPECT_EQ(req.body, LARGE_DATA);
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
              [&](const Request &req, Response &res,
                  const ContentReader &content_reader) {
                if (req.is_multipart_form_data()) {
                  MultipartFormDataItems files;
                  content_reader(
                      [&](const MultipartFormData &file) {
                        files.push_back(file);
                        return true;
                      },
                      [&](const char *data, size_t data_length) {
                        files.back().content.append(data, data_length);
                        return true;
                      });

                  EXPECT_EQ(5u, files.size());

                  {
                    const auto &file = get_file_value(files, "text1");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("text default", file.content);
                  }

                  {
                    const auto &file = get_file_value(files, "text2");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("aωb", file.content);
                  }

                  {
                    const auto &file = get_file_value(files, "file1");
                    EXPECT_EQ("hello.txt", file.filename);
                    EXPECT_EQ("text/plain", file.content_type);
                    EXPECT_EQ("h\ne\n\nl\nl\no\n", file.content);
                  }

                  {
                    const auto &file = get_file_value(files, "file3");
                    EXPECT_EQ("", file.filename);
                    EXPECT_EQ("application/octet-stream", file.content_type);
                    EXPECT_EQ(0u, file.content.size());
                  }
                } else {
                  std::string body;
                  content_reader([&](const char *data, size_t data_length) {
                    EXPECT_EQ(data_length, 7);
                    body.append(data, data_length);
                    return true;
                  });
                  EXPECT_EQ(body, "content");
                  res.set_content(body, "text/plain");
                }
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
        .Post("/query-string-and-body",
              [&](const Request &req, Response & /*res*/) {
                ASSERT_TRUE(req.has_param("key"));
                EXPECT_EQ(req.get_param_value("key"), "value");
                EXPECT_EQ(req.body, "content");
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
                  EXPECT_EQ("test", file.content);
                }

                {
                  const auto &file = req.get_file_value("key2");
                  EXPECT_EQ("", file.filename);
                  EXPECT_EQ("--abcdefg123", file.content);
                }
              })
#endif
        ;

    persons_["john"] = "programmer";

    t_ = thread([&]() { ASSERT_TRUE(svr_.listen(HOST, PORT)); });

    while (!svr_.is_running()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
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

TEST_F(ServerTest, GetMethod200withPercentEncoding) {
  auto res = cli_.Get("/%68%69"); // auto res = cli_.Get("/hi");
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

TEST_F(ServerTest, HeadMethod200Static) {
  auto res = cli_.Head("/mount/dir/index.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ(104, std::stoi(res->get_header_value("Content-Length")));
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

TEST_F(ServerTest, PutMethod3) {
  auto res = cli_.Get("/person/john3");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(404, res->status);

  Params params;
  params.emplace("name", "john3");
  params.emplace("note", "coder");

  res = cli_.Put("/person", params);
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);

  res = cli_.Get("/person/john3");
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

TEST_F(ServerTest, GetMethodDirMountTest) {
  auto res = cli_.Get("/mount/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirMountTestWithDoubleDots) {
  auto res = cli_.Get("/mount/dir/../dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidMountPath) {
  auto res = cli_.Get("/mount/dir/../test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDirMount) {
  auto res = cli_.Get("/mount/../www2/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDirMount2) {
  auto res = cli_.Get("/mount/dir/../../www2/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, UserDefinedMIMETypeMapping) {
  auto res = cli_.Get("/dir/test.abcde");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/abcde", res->get_header_value("Content-Type"));
  EXPECT_EQ("abcde", res->body);
}

TEST_F(ServerTest, InvalidBaseDirMount) {
  EXPECT_EQ(false, svr_.set_mount_point("invalid_mount_point", "./www3"));
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
  uint64_t offset = 0;
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

TEST_F(ServerTest, GetStreamedChunked2) {
  auto res = cli_.Get("/streamed-chunked2");
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
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
      [](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        ASSERT_TRUE(sink.is_writable());
        sink.write("PUT", 3);
      },
      "text/plain");

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, PutWithContentProviderWithGzip) {
  cli_.set_compress(true);
  auto res = cli_.Put(
      "/put", 3,
      [](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        ASSERT_TRUE(sink.is_writable());
        sink.write("PUT", 3);
      },
      "text/plain");

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PutLargeFileWithGzip) {
  cli_.set_compress(true);
  auto res = cli_.Put("/put-large", LARGE_DATA, "text/plain");

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(LARGE_DATA, res->body);
}

TEST_F(ServerTest, PutContentWithDeflate) {
  cli_.set_compress(false);
  httplib::Headers headers;
  headers.emplace("Content-Encoding", "deflate");
  // PUT in deflate format:
  auto res = cli_.Put("/put", headers, "\170\234\013\010\015\001\0\001\361\0\372", "text/plain");

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

TEST_F(ServerTest, PostMulitpartFilsContentReceiver) {
  MultipartFormDataItems items = {
      {"text1", "text default", "", ""},
      {"text2", "aωb", "", ""},
      {"file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain"},
      {"file2", "{\n  \"world\", true\n}\n", "world.json", "application/json"},
      {"file3", "", "", "application/octet-stream"},
  };

  auto res = cli_.Post("/content_receiver", items);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PostContentReceiverGzip) {
  cli_.set_compress(true);
  auto res = cli_.Post("/content_receiver", "content", "text/plain");
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

TEST_F(ServerTest, PostQueryStringAndBody) {
  auto res =
      cli_.Post("/query-string-and-body?key=value", "content", "text/plain");
  ASSERT_TRUE(res != nullptr);
  ASSERT_EQ(200, res->status);
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

  cli_.set_compress(true);
  auto res = cli_.Post("/gzipmultipart", items);

  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);
}
#endif

// Sends a raw request to a server listening at HOST:PORT.
static bool send_request(time_t read_timeout_sec, const std::string &req) {
  auto client_sock = detail::create_client_socket(HOST, PORT, /*timeout_sec=*/5,
                                                  std::string());

  if (client_sock == INVALID_SOCKET) { return false; }

  return detail::process_and_close_socket(
      true, client_sock, 1, read_timeout_sec, 0,
      [&](Stream &strm, bool /*last_connection*/, bool &
          /*connection_close*/) -> bool {
        if (req.size() !=
            static_cast<size_t>(strm.write(req.data(), req.size()))) {
          return false;
        }

        char buf[512];

        detail::stream_line_reader line_reader(strm, buf, sizeof(buf));
        while (line_reader.getline()) {}
        return true;
      });
}

TEST(ServerRequestParsingTest, TrimWhitespaceFromHeaderValues) {
  Server svr;
  std::string header_value;
  svr.Get("/validate-ws-in-headers", [&](const Request &req, Response &res) {
    header_value = req.get_header_value("foo");
    res.set_content("ok", "text/plain");
  });

  thread t = thread([&] { svr.listen(HOST, PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Only space and horizontal tab are whitespace. Make sure other whitespace-
  // like characters are not treated the same - use vertical tab and escape.
  const std::string req = "GET /validate-ws-in-headers HTTP/1.1\r\n"
                          "foo: \t \v bar \e\t \r\n"
                          "Connection: close\r\n"
                          "\r\n";

  ASSERT_TRUE(send_request(5, req));
  svr.stop();
  t.join();
  EXPECT_EQ(header_value, "\v bar \e");
}

// Sends a raw request and verifies that there isn't a crash or exception.
static void test_raw_request(const std::string& req) {
  Server svr;
  svr.Get("/hi", [&](const Request & /*req*/, Response &res) {
    res.set_content("ok", "text/plain");
  });

  // Server read timeout must be longer than the client read timeout for the
  // bug to reproduce, probably to force the server to process a request
  // without a trailing blank line.
  const time_t client_read_timeout_sec = 1;
  svr.set_read_timeout(client_read_timeout_sec + 1, 0);
  bool listen_thread_ok = false;
  thread t = thread([&] { listen_thread_ok = svr.listen(HOST, PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(send_request(client_read_timeout_sec, req));
  svr.stop();
  t.join();
  EXPECT_TRUE(listen_thread_ok);
}

TEST(ServerRequestParsingTest, ReadHeadersRegexComplexity) {
  // A certain header line causes an exception if the header property is parsed
  // naively with a single regex. This occurs with libc++ but not libstdc++.
  test_raw_request(
      "GET /hi HTTP/1.1\r\n"
      " :                                                                      "
      "                                                                       "
  );
}

TEST(ServerRequestParsingTest, ReadHeadersRegexComplexity2) {
  // A certain header line causes an exception if the header property *name* is
  // parsed with a regular expression starting with "(.+?):" - this is a non-
  // greedy matcher and requires backtracking when there are a lot of ":"
  // characters.
  // This occurs with libc++ but not libstdc++.
  test_raw_request(
      "GET /hi HTTP/1.1\r\n"
      ":-:::::::::::::::::::::::::::-::::::::::::::::::::::::@-&&&&&&&&&&&"
      "--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&"
      "&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-:::::"
      "::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-::::::::::::::::::::::::"
      ":::::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-:::::::::::::::::::::"
      "::::::::-:::::::::::::::::@-&&&&&&&--:::::::-::::::::::::::::::::::"
      ":::::::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-:::::::::::::::::::"
      "::::::::::-:::::::::::::::::@-&&&&&::::::::::::-:::::::::::::::::@-"
      "&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-::::::::::::::::"
      ":@-&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::"
      "::::@-&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-::::::@-&&"
      "&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@"
      "::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&&&&"
      "--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&"
      "&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&"
      "&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@-&&"
      "&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::::@"
      "-&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::::"
      "::@-&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-::::::::::::"
      ":::::@-&&&&&&&&&&&::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-::::::"
      ":::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-:::"
      "::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&&&&--:::::::-"
      ":::::::::::::::::::::::::::::-:::::::::::::::::@-&&&&&&&&&&&---&&:&"
      "&&.0------------:-:::::::::::::::::::::::::::::-:::::::::::::::::@-"
      "&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-::::::::::::::::"
      ":@-&&&&&&&&&&&--:::::::-:::::::::::::::::::::::::::::-:::::::::::::"
      "::::@-&&&&&&&&&&&---&&:&&&.0------------O--------\rH PUTHTTP/1.1\r\n"
      "&&&%%%");
}

TEST(ServerStopTest, StopServerWithChunkedTransmission) {
  Server svr;

  svr.Get("/events", [](const Request & /*req*/, Response &res) {
    res.set_header("Content-Type", "text/event-stream");
    res.set_header("Cache-Control", "no-cache");
    res.set_chunked_content_provider([](size_t offset, const DataSink &sink) {
      char buffer[27];
      int size = sprintf(buffer, "data:%ld\n\n", offset);
      sink.write(buffer, size);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    });
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  Client client(HOST, PORT);
  const Headers headers = {{"Accept", "text/event-stream"},
                           {"Connection", "Keep-Alive"}};

  auto get_thread = std::thread([&client, &headers]() {
    std::shared_ptr<Response> res = client.Get(
        "/events", headers,
        [](const char * /*data*/, size_t /*len*/) -> bool { return true; });
  });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(2));

  svr.stop();

  listen_thread.join();
  get_thread.join();

  ASSERT_FALSE(svr.is_running());
}

TEST(MountTest, Unmount) {
  Server svr;

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  svr.set_mount_point("/mount2", "./www2");

  auto res = cli.Get("/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);

  res = cli.Get("/mount2/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);

  svr.set_mount_point("/", "./www");

  res = cli.Get("/dir/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(200, res->status);

  svr.remove_mount_point("/");
  res = cli.Get("/dir/");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);

  svr.remove_mount_point("/mount2");
  res = cli.Get("/mount2/dir/test.html");
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(404, res->status);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

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
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      ASSERT_TRUE(svr_.listen_after_bind());
    });

    while (!svr_.is_running()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  httplib::SSLClient cli(HOST, PORT, CLIENT_CERT_FILE, CLIENT_PRIVATE_KEY_FILE);
  auto res = cli.Get("/test");
  cli.set_timeout_sec(30);
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
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  httplib::SSLClient cli(HOST, PORT);
  auto res = cli.Get("/test");
  cli.set_timeout_sec(30);
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
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  httplib::SSLClient cli(HOST, PORT, CLIENT_CERT_FILE, CLIENT_PRIVATE_KEY_FILE);
  auto res = cli.Get("/test");
  cli.set_timeout_sec(30);
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
