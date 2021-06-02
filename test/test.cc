#include <httplib.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <sstream>
#include <stdexcept>
#include <thread>

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_CERT2_FILE "./cert2.pem"
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

TEST(EncodeQueryParamTest, ParseUnescapedChararactersTest) {
  string unescapedCharacters = "-_.!~*'()";

  EXPECT_EQ(detail::encode_query_param(unescapedCharacters), "-_.!~*'()");
}

TEST(EncodeQueryParamTest, ParseReservedCharactersTest) {
  string reservedCharacters = ";,/?:@&=+$";

  EXPECT_EQ(detail::encode_query_param(reservedCharacters),
            "%3B%2C%2F%3F%3A%40%26%3D%2B%24");
}

TEST(EncodeQueryParamTest, TestUTF8Characters) {
  string chineseCharacters = "中国語";
  string russianCharacters = "дом";
  string brazilianCharacters = "óculos";

  EXPECT_EQ(detail::encode_query_param(chineseCharacters),
            "%E4%B8%AD%E5%9B%BD%E8%AA%9E");

  EXPECT_EQ(detail::encode_query_param(russianCharacters),
            "%D0%B4%D0%BE%D0%BC");

  EXPECT_EQ(detail::encode_query_param(brazilianCharacters), "%C3%B3culos");
}

TEST(TrimTests, TrimStringTests) {
  EXPECT_EQ("abc", detail::trim_copy("abc"));
  EXPECT_EQ("abc", detail::trim_copy("  abc  "));
  EXPECT_TRUE(detail::trim_copy("").empty());
}

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

TEST(SplitTest, ParseInvalidQueryTests) {

  {
    string s = " ";
    Params dict;
    detail::parse_query_text(s, dict);
    EXPECT_TRUE(dict.empty());
  }

  {
    string s = " = =";
    Params dict;
    detail::parse_query_text(s, dict);
    EXPECT_TRUE(dict.empty());
  }
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
  auto val =
      detail::get_header_value<uint64_t>(headers, "Content-Length", 0, 100);
  EXPECT_EQ(100ull, val);
}

TEST(GetHeaderValueTest, RegularValue) {
  Headers headers = {{"Content-Type", "text/html"}, {"Dummy", "Dummy"}};
  auto val = detail::get_header_value(headers, "Content-Type", 0, "text/plain");
  EXPECT_STREQ("text/html", val);
}

TEST(GetHeaderValueTest, SetContent) {
  Response res;

  res.set_content("html", "text/html");
  EXPECT_EQ("text/html", res.get_header_value("Content-Type"));

  res.set_content("text", "text/plain");
  EXPECT_EQ(1, res.get_header_value_count("Content-Type"));
  EXPECT_EQ("text/plain", res.get_header_value("Content-Type"));
}

TEST(GetHeaderValueTest, RegularValueInt) {
  Headers headers = {{"Content-Length", "100"}, {"Dummy", "Dummy"}};
  auto val =
      detail::get_header_value<uint64_t>(headers, "Content-Length", 0, 0);
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

TEST(ParseAcceptEncoding1, AcceptEncoding) {
  Request req;
  req.set_header("Accept-Encoding", "gzip");

  Response res;
  res.set_header("Content-Type", "text/plain");

  auto ret = detail::encoding_type(req, res);

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
  EXPECT_TRUE(ret == detail::EncodingType::Gzip);
#else
  EXPECT_TRUE(ret == detail::EncodingType::None);
#endif
}

TEST(ParseAcceptEncoding2, AcceptEncoding) {
  Request req;
  req.set_header("Accept-Encoding", "gzip, deflate, br");

  Response res;
  res.set_header("Content-Type", "text/plain");

  auto ret = detail::encoding_type(req, res);

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
  EXPECT_TRUE(ret == detail::EncodingType::Brotli);
#elif CPPHTTPLIB_ZLIB_SUPPORT
  EXPECT_TRUE(ret == detail::EncodingType::Gzip);
#else
  EXPECT_TRUE(ret == detail::EncodingType::None);
#endif
}

TEST(ParseAcceptEncoding3, AcceptEncoding) {
  Request req;
  req.set_header("Accept-Encoding", "br;q=1.0, gzip;q=0.8, *;q=0.1");

  Response res;
  res.set_header("Content-Type", "text/plain");

  auto ret = detail::encoding_type(req, res);

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
  EXPECT_TRUE(ret == detail::EncodingType::Brotli);
#elif CPPHTTPLIB_ZLIB_SUPPORT
  EXPECT_TRUE(ret == detail::EncodingType::Gzip);
#else
  EXPECT_TRUE(ret == detail::EncodingType::None);
#endif
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
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(2);

  auto res =
      cli.Get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137");
  ASSERT_TRUE(res);

  std::string out;
  detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, res->body);
}

TEST(ChunkedEncodingTest, WithContentReceiver) {
  auto host = "www.httpwatch.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(2);

  std::string body;
  auto res =
      cli.Get("/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137",
              [&](const char *data, size_t data_length) {
                body.append(data, data_length);
                return true;
              });
  ASSERT_TRUE(res);

  std::string out;
  detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, body);
}

TEST(ChunkedEncodingTest, WithResponseHandlerAndContentReceiver) {
  auto host = "www.httpwatch.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(2);

  std::string body;
  auto res = cli.Get(
      "/httpgallery/chunked/chunkedimage.aspx?0.4153841143030137",
      [&](const Response &response) {
        EXPECT_EQ(200, response.status);
        return true;
      },
      [&](const char *data, size_t data_length) {
        body.append(data, data_length);
        return true;
      });
  ASSERT_TRUE(res);

  std::string out;
  detail::read_file("./image.jpg", out);

  EXPECT_EQ(200, res->status);
  EXPECT_EQ(out, body);
}

TEST(RangeTest, FromHTTPBin) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(5);

  {
    auto res = cli.Get("/range/32");
    ASSERT_TRUE(res);
    EXPECT_EQ("abcdefghijklmnopqrstuvwxyzabcdef", res->body);
    EXPECT_EQ(200, res->status);
  }

  {
    Headers headers = {make_range_header({{1, -1}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ("bcdefghijklmnopqrstuvwxyzabcdef", res->body);
    EXPECT_EQ(206, res->status);
  }

  {
    Headers headers = {make_range_header({{1, 10}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ("bcdefghijk", res->body);
    EXPECT_EQ(206, res->status);
  }

  {
    Headers headers = {make_range_header({{0, 31}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ("abcdefghijklmnopqrstuvwxyzabcdef", res->body);
    EXPECT_EQ(200, res->status);
  }

  {
    Headers headers = {make_range_header({{0, -1}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ("abcdefghijklmnopqrstuvwxyzabcdef", res->body);
    EXPECT_EQ(200, res->status);
  }

  {
    Headers headers = {make_range_header({{0, 32}})};
    auto res = cli.Get("/range/32", headers);
    ASSERT_TRUE(res);
    EXPECT_EQ(416, res->status);
  }
}

TEST(ConnectionErrorTest, InvalidHost) {
  auto host = "-abcde.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(std::chrono::seconds(2));

  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Connection, res.error());
}

TEST(ConnectionErrorTest, InvalidHost2) {
  auto host = "httpbin.org/";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif
  cli.set_connection_timeout(std::chrono::seconds(2));

  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Connection, res.error());
}

TEST(ConnectionErrorTest, InvalidHostCheckResultErrorToString) {
  auto host = "httpbin.org/";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif
  cli.set_connection_timeout(std::chrono::seconds(2));

  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  stringstream s;
  s << "error code: " << res.error();
  EXPECT_EQ("error code: 2", s.str());
}

TEST(ConnectionErrorTest, InvalidPort) {
  auto host = "localhost";
  auto port = 44380;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host, port);
#else
  Client cli(host, port);
#endif
  cli.set_connection_timeout(std::chrono::seconds(2));

  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Connection, res.error());
}

TEST(ConnectionErrorTest, Timeout) {
  auto host = "google.com";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 44380;
  SSLClient cli(host, port);
#else
  auto port = 8080;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(std::chrono::seconds(2));

  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  EXPECT_TRUE(res.error() == Error::Connection);
}

TEST(CancelTest, NoCancel) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(std::chrono::seconds(5));

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return true; });
  ASSERT_TRUE(res);
  EXPECT_EQ("abcdefghijklmnopqrstuvwxyzabcdef", res->body);
  EXPECT_EQ(200, res->status);
}

TEST(CancelTest, WithCancelSmallPayload) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif

  auto res = cli.Get("/range/32", [](uint64_t, uint64_t) { return false; });
  cli.set_connection_timeout(std::chrono::seconds(5));
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST(CancelTest, WithCancelLargePayload) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif
  cli.set_connection_timeout(std::chrono::seconds(5));

  uint32_t count = 0;
  auto res = cli.Get("/range/65536",
                     [&count](uint64_t, uint64_t) { return (count++ == 0); });
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST(BaseAuthTest, FromHTTPWatch) {
  auto host = "httpbin.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  auto port = 443;
  SSLClient cli(host, port);
#else
  auto port = 80;
  Client cli(host, port);
#endif

  {
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res);
    EXPECT_EQ(401, res->status);
  }

  {
    auto res = cli.Get("/basic-auth/hello/world",
                       {make_basic_authentication_header("hello", "world")});
    ASSERT_TRUE(res);
    EXPECT_EQ("{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n",
              res->body);
    EXPECT_EQ(200, res->status);
  }

  {
    cli.set_basic_auth("hello", "world");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res);
    EXPECT_EQ("{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n",
              res->body);
    EXPECT_EQ(200, res->status);
  }

  {
    cli.set_basic_auth("hello", "bad");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res);
    EXPECT_EQ(401, res->status);
  }

  {
    cli.set_basic_auth("bad", "world");
    auto res = cli.Get("/basic-auth/hello/world");
    ASSERT_TRUE(res);
    EXPECT_EQ(401, res->status);
  }
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(DigestAuthTest, FromHTTPWatch) {
  auto host = "httpbin.org";
  auto port = 443;
  SSLClient cli(host, port);

  {
    auto res = cli.Get("/digest-auth/auth/hello/world");
    ASSERT_TRUE(res);
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
      ASSERT_TRUE(res);
      EXPECT_EQ("{\n  \"authenticated\": true, \n  \"user\": \"hello\"\n}\n",
                res->body);
      EXPECT_EQ(200, res->status);
    }

    cli.set_digest_auth("hello", "bad");
    for (auto path : paths) {
      auto res = cli.Get(path.c_str());
      ASSERT_TRUE(res);
      EXPECT_EQ(401, res->status);
    }

    // NOTE: Until httpbin.org fixes issue #46, the following test is commented
    // out. Plese see https://httpbin.org/digest-auth/auth/hello/world
    // cli.set_digest_auth("bad", "world");
    // for (auto path : paths) {
    //   auto res = cli.Get(path.c_str());
    //   ASSERT_TRUE(res);
    //   EXPECT_EQ(400, res->status);
    // }
  }
}
#endif

TEST(AbsoluteRedirectTest, Redirect) {
  auto host = "nghttp2.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif

  cli.set_follow_location(true);
  auto res = cli.Get("/httpbin/absolute-redirect/3");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(RedirectTest, Redirect) {
  auto host = "nghttp2.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif

  cli.set_follow_location(true);
  auto res = cli.Get("/httpbin/redirect/3");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(RelativeRedirectTest, Redirect) {
  auto host = "nghttp2.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif

  cli.set_follow_location(true);
  auto res = cli.Get("/httpbin/relative-redirect/3");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(TooManyRedirectTest, Redirect) {
  auto host = "nghttp2.org";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  SSLClient cli(host);
#else
  Client cli(host);
#endif

  cli.set_follow_location(true);
  auto res = cli.Get("/httpbin/redirect/21");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::ExceedRedirectCount, res.error());
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(YahooRedirectTest, Redirect) {
  Client cli("yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(301, res->status);

  cli.set_follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("https://yahoo.com/", res->location);
}

TEST(HttpsToHttpRedirectTest, Redirect) {
  SSLClient cli("nghttp2.org");
  cli.set_follow_location(true);
  auto res = cli.Get(
      "/httpbin/redirect-to?url=http%3A%2F%2Fwww.google.com&status_code=302");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest2, Redirect) {
  SSLClient cli("nghttp2.org");
  cli.set_follow_location(true);

  Params params;
  params.emplace("url", "http://www.google.com");
  params.emplace("status_code", "302");

  auto res = cli.Get("/httpbin/redirect-to", params, Headers{});
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest3, Redirect) {
  SSLClient cli("nghttp2.org");
  cli.set_follow_location(true);

  Params params;
  params.emplace("url", "http://www.google.com");

  auto res = cli.Get("/httpbin/redirect-to?status_code=302", params, Headers{});
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(RedirectToDifferentPort, Redirect) {
  Server svr8080;
  Server svr8081;

  svr8080.Get("/1", [&](const Request & /*req*/, Response &res) {
    res.set_redirect("http://localhost:8081/2");
  });

  svr8081.Get("/2", [&](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  auto thread8080 = std::thread([&]() { svr8080.listen("localhost", 8080); });

  auto thread8081 = std::thread([&]() { svr8081.listen("localhost", 8081); });

  while (!svr8080.is_running() || !svr8081.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", 8080);
  cli.set_follow_location(true);

  auto res = cli.Get("/1");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("Hello World!", res->body);

  svr8080.stop();
  svr8081.stop();
  thread8080.join();
  thread8081.join();
  ASSERT_FALSE(svr8080.is_running());
  ASSERT_FALSE(svr8081.is_running());
}

TEST(UrlWithSpace, Redirect) {
  SSLClient cli("edge.forgecdn.net");
  cli.set_follow_location(true);

  auto res = cli.Get("/files/2595/310/Neat 1.4-17.jar");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(18527, res->get_header_value<uint64_t>("Content-Length"));
}

TEST(RedirectFromPageWithContent, Redirect) {
  Server svr;

  svr.Get("/1", [&](const Request & /*req*/, Response &res) {
    res.set_content("___", "text/plain");
    res.set_redirect("/2");
  });

  svr.Get("/2", [&](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  auto th = std::thread([&]() { svr.listen("localhost", PORT); });

  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli("localhost", PORT);
    cli.set_follow_location(true);

    std::string body;
    auto res = cli.Get("/1", [&](const char *data, size_t data_length) {
      body.append(data, data_length);
      return true;
    });

    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("Hello World!", body);
  }

  {
    Client cli("localhost", PORT);

    std::string body;
    auto res = cli.Get("/1", [&](const char *data, size_t data_length) {
      body.append(data, data_length);
      return true;
    });

    ASSERT_TRUE(res);
    EXPECT_EQ(302, res->status);
    EXPECT_EQ("___", body);
  }

  svr.stop();
  th.join();
  ASSERT_FALSE(svr.is_running());
}

#endif

TEST(PathUrlEncodeTest, PathUrlEncode) {
  Server svr;

  svr.Get("/foo", [](const Request &req, Response &res) {
    auto a = req.params.find("a");
    if (a != req.params.end()) {
      res.set_content((*a).second, "text/plain");
      res.status = 200;
    } else {
      res.status = 400;
    }
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);
    cli.set_url_encode(false);

    auto res = cli.Get("/foo?a=explicitly+encoded");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    // This expects it back with a space, as the `+` won't have been
    // url-encoded, and server-side the params get decoded turning `+`
    // into spaces.
    EXPECT_EQ("explicitly encoded", res->body);
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(BindServerTest, BindDualStack) {
  Server svr;

  svr.Get("/1", [&](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  auto thread = std::thread([&]() { svr.listen("::", PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli("127.0.0.1", PORT);

    auto res = cli.Get("/1");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("Hello World!", res->body);
  }
  {
    Client cli("::1", PORT);

    auto res = cli.Get("/1");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("Hello World!", res->body);
  }
  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(BindServerTest, BindAndListenSeparately) {
  Server svr;
  int port = svr.bind_to_any_port("0.0.0.0");
  ASSERT_TRUE(svr.is_valid());
  ASSERT_TRUE(port > 0);
  svr.stop();
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(BindServerTest, BindAndListenSeparatelySSL) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE,
                CLIENT_CA_CERT_DIR);
  int port = svr.bind_to_any_port("0.0.0.0");
  ASSERT_TRUE(svr.is_valid());
  ASSERT_TRUE(port > 0);
  svr.stop();
}
#endif

TEST(ErrorHandlerTest, ContentLength) {
  Server svr;

  svr.set_error_handler([](const Request & /*req*/, Response &res) {
    res.status = 200;
    res.set_content("abcdefghijklmnopqrstuvwxyz",
                    "text/html"); // <= Content-Length still 13
  });

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
    res.status = 524;
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/hi");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
    EXPECT_EQ("26", res->get_header_value("Content-Length"));
    EXPECT_EQ("abcdefghijklmnopqrstuvwxyz", res->body);
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(ExceptionHandlerTest, ContentLength) {
  Server svr;

  svr.set_exception_handler(
      [](const Request & /*req*/, Response &res, std::exception & /*e*/) {
        res.status = 500;
        res.set_content("abcdefghijklmnopqrstuvwxyz",
                        "text/html"); // <= Content-Length still 13
      });

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
    throw std::runtime_error("abc");
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/hi");
    ASSERT_TRUE(res);
    EXPECT_EQ(500, res->status);
    EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
    EXPECT_EQ("26", res->get_header_value("Content-Length"));
    EXPECT_EQ("abcdefghijklmnopqrstuvwxyz", res->body);
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(NoContentTest, ContentLength) {
  Server svr;

  svr.Get("/hi",
          [](const Request & /*req*/, Response &res) { res.status = 204; });
  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/hi");
    ASSERT_TRUE(res);
    EXPECT_EQ(204, res->status);
    EXPECT_EQ("0", res->get_header_value("Content-Length"));
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(RoutingHandlerTest, PreRoutingHandler) {
  Server svr;

  svr.set_pre_routing_handler([](const Request &req, Response &res) {
    if (req.path == "/routing_handler") {
      res.set_header("PRE_ROUTING", "on");
      res.set_content("Routing Handler", "text/plain");
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });

  svr.set_error_handler([](const Request & /*req*/, Response &res) {
    res.set_content("Error", "text/html");
  });

  svr.set_post_routing_handler([](const Request &req, Response &res) {
    if (req.path == "/routing_handler") {
      res.set_header("POST_ROUTING", "on");
    }
  });

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/routing_handler");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("Routing Handler", res->body);
    EXPECT_EQ(1, res->get_header_value_count("PRE_ROUTING"));
    EXPECT_EQ("on", res->get_header_value("PRE_ROUTING"));
    EXPECT_EQ(1, res->get_header_value_count("POST_ROUTING"));
    EXPECT_EQ("on", res->get_header_value("POST_ROUTING"));
  }

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/hi");
    ASSERT_TRUE(res);
    EXPECT_EQ(200, res->status);
    EXPECT_EQ("Hello World!\n", res->body);
    EXPECT_EQ(0, res->get_header_value_count("PRE_ROUTING"));
    EXPECT_EQ(0, res->get_header_value_count("POST_ROUTING"));
  }

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/aaa");
    ASSERT_TRUE(res);
    EXPECT_EQ(404, res->status);
    EXPECT_EQ("Error", res->body);
    EXPECT_EQ(0, res->get_header_value_count("PRE_ROUTING"));
    EXPECT_EQ(0, res->get_header_value_count("POST_ROUTING"));
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(InvalidFormatTest, StatusCode) {
  Server svr;

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
    res.status = 9999; // Status should be a three-digit code...
  });

  auto thread = std::thread([&]() { svr.listen(HOST, PORT); });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  {
    Client cli(HOST, PORT);

    auto res = cli.Get("/hi");
    ASSERT_FALSE(res);
  }

  svr.stop();
  thread.join();
  ASSERT_FALSE(svr.is_running());
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    cli_.enable_server_certificate_verification(false);
#endif
  }

  virtual void SetUp() {
    svr_.set_mount_point("/", "./www");
    svr_.set_mount_point("/mount", "./www2");
    svr_.set_file_extension_and_mimetype_mapping("abcde", "text/abcde");

    svr_.Get("/hi",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("Hello World!", "text/plain");
             })
        .Get("/http_response_splitting",
             [&](const Request & /*req*/, Response &res) {
               res.set_header("a", "1\r\nSet-Cookie: a=1");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_header("a", "1\nSet-Cookie: a=1");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_header("a", "1\rSet-Cookie: a=1");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_header("a\r\nb", "0");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_header("a\rb", "0");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_header("a\nb", "0");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("a"));

               res.set_redirect("1\r\nSet-Cookie: a=1");
               EXPECT_EQ(0, res.headers.size());
               EXPECT_FALSE(res.has_header("Location"));
             })
        .Get("/slow",
             [&](const Request & /*req*/, Response &res) {
               std::this_thread::sleep_for(std::chrono::seconds(2));
               res.set_content("slow", "text/plain");
             })
        .Post("/slowpost",
              [&](const Request & /*req*/, Response &res) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                res.set_content("slow", "text/plain");
              })
        .Get("/remote_addr",
             [&](const Request &req, Response &res) {
               auto remote_addr = req.headers.find("REMOTE_ADDR")->second;
               EXPECT_TRUE(req.has_header("REMOTE_PORT"));
               EXPECT_EQ(req.remote_addr, req.get_header_value("REMOTE_ADDR"));
               EXPECT_EQ(req.remote_port,
                         std::stoi(req.get_header_value("REMOTE_PORT")));
               res.set_content(remote_addr.c_str(), "text/plain");
             })
        .Get("/endwith%",
             [&](const Request & /*req*/, Response &res) {
               res.set_content("Hello World!", "text/plain");
             })
        .Get("/a\\+\\+b",
             [&](const Request &req, Response &res) {
               ASSERT_TRUE(req.has_param("a +b"));
               auto val = req.get_param_value("a +b");
               res.set_content(val, "text/plain");
             })
        .Get("/", [&](const Request & /*req*/,
                      Response &res) { res.set_redirect("/hi"); })
        .Post("/1", [](const Request & /*req*/,
                       Response &res) { res.set_redirect("/2", 303); })
        .Get("/2",
             [](const Request & /*req*/, Response &res) {
               res.set_content("redirected.", "text/plain");
               res.status = 200;
             })
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
                   "text/plain", [](size_t /*offset*/, DataSink &sink) {
                     EXPECT_TRUE(sink.is_writable());
                     sink.os << "123";
                     sink.os << "456";
                     sink.os << "789";
                     sink.done();
                     return true;
                   });
             })
        .Get("/streamed-chunked2",
             [&](const Request & /*req*/, Response &res) {
               auto i = new int(0);
               res.set_chunked_content_provider(
                   "text/plain",
                   [i](size_t /*offset*/, DataSink &sink) {
                     EXPECT_TRUE(sink.is_writable());
                     switch (*i) {
                     case 0: sink.os << "123"; break;
                     case 1: sink.os << "456"; break;
                     case 2: sink.os << "789"; break;
                     case 3: sink.done(); break;
                     }
                     (*i)++;
                     return true;
                   },
                   [i](bool success) {
                     EXPECT_TRUE(success);
                     delete i;
                   });
             })
        .Get("/streamed",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(
                   6, "text/plain",
                   [](size_t offset, size_t /*length*/, DataSink &sink) {
                     sink.os << (offset < 3 ? "a" : "b");
                     return true;
                   });
             })
        .Get("/streamed-with-range",
             [&](const Request & /*req*/, Response &res) {
               auto data = new std::string("abcdefg");
               res.set_content_provider(
                   data->size(), "text/plain",
                   [data](size_t offset, size_t length, DataSink &sink) {
                     EXPECT_TRUE(sink.is_writable());
                     size_t DATA_CHUNK_SIZE = 4;
                     const auto &d = *data;
                     auto out_len =
                         std::min(static_cast<size_t>(length), DATA_CHUNK_SIZE);
                     auto ret =
                         sink.write(&d[static_cast<size_t>(offset)], out_len);
                     EXPECT_TRUE(ret);
                     return true;
                   },
                   [data](bool success) {
                     EXPECT_TRUE(success);
                     delete data;
                   });
             })
        .Get("/streamed-cancel",
             [&](const Request & /*req*/, Response &res) {
               res.set_content_provider(
                   size_t(-1), "text/plain",
                   [](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
                     EXPECT_TRUE(sink.is_writable());
                     sink.os << "data_chunk";
                     return true;
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
                EXPECT_EQ(6u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));
                ASSERT_TRUE(req.body.empty());

                {
                  const auto &file = req.get_file_value("text1");
                  EXPECT_TRUE(file.filename.empty());
                  EXPECT_EQ("text default", file.content);
                }

                {
                  const auto &file = req.get_file_value("text2");
                  EXPECT_TRUE(file.filename.empty());
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
                  EXPECT_TRUE(file.filename.empty());
                  EXPECT_EQ("application/octet-stream", file.content_type);
                  EXPECT_EQ(0u, file.content.size());
                }

                {
                  const auto &file = req.get_file_value("file4");
                  EXPECT_TRUE(file.filename.empty());
                  EXPECT_EQ(0u, file.content.size());
                  EXPECT_EQ("application/json  tmp-string", file.content_type);
                }
              })
        .Post("/empty",
              [&](const Request &req, Response &res) {
                EXPECT_EQ(req.body, "");
                EXPECT_EQ("text/plain", req.get_header_value("Content-Type"));
                EXPECT_EQ("0", req.get_header_value("Content-Length"));
                res.set_content("empty", "text/plain");
              })
        .Post("/empty-no-content-type",
              [&](const Request &req, Response &res) {
                EXPECT_EQ(req.body, "");
                EXPECT_FALSE(req.has_header("Content-Type"));
                EXPECT_EQ("0", req.get_header_value("Content-Length"));
                res.set_content("empty-no-content-type", "text/plain");
              })
        .Put("/empty-no-content-type",
             [&](const Request &req, Response &res) {
               EXPECT_EQ(req.body, "");
               EXPECT_FALSE(req.has_header("Content-Type"));
               EXPECT_EQ("0", req.get_header_value("Content-Length"));
               res.set_content("empty-no-content-type", "text/plain");
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
        .Delete("/delete-body",
                [&](const Request &req, Response &res) {
                  EXPECT_EQ(req.body, "content");
                  res.set_content(req.body, "text/plain");
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
                    EXPECT_TRUE(file.filename.empty());
                    EXPECT_EQ("text default", file.content);
                  }

                  {
                    const auto &file = get_file_value(files, "text2");
                    EXPECT_TRUE(file.filename.empty());
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
                    EXPECT_TRUE(file.filename.empty());
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
        .Get("/last-request",
             [&](const Request &req, Response & /*res*/) {
               EXPECT_EQ("close", req.get_header_value("Connection"));
             })
        .Get(R"(/redirect/(\d+))",
             [&](const Request &req, Response &res) {
               auto num = std::stoi(req.matches[1]) + 1;
               std::string url = "/redirect/" + std::to_string(num);
               res.set_redirect(url);
             })
        .Post("/binary",
              [&](const Request &req, Response &res) {
                EXPECT_EQ(4, req.body.size());
                EXPECT_EQ("application/octet-stream",
                          req.get_header_value("Content-Type"));
                EXPECT_EQ("4", req.get_header_value("Content-Length"));
                res.set_content(req.body, "application/octet-stream");
              })
        .Put("/binary",
             [&](const Request &req, Response &res) {
               EXPECT_EQ(4, req.body.size());
               EXPECT_EQ("application/octet-stream",
                         req.get_header_value("Content-Type"));
               EXPECT_EQ("4", req.get_header_value("Content-Length"));
               res.set_content(req.body, "application/octet-stream");
             })
        .Patch("/binary",
               [&](const Request &req, Response &res) {
                 EXPECT_EQ(4, req.body.size());
                 EXPECT_EQ("application/octet-stream",
                           req.get_header_value("Content-Type"));
                 EXPECT_EQ("4", req.get_header_value("Content-Length"));
                 res.set_content(req.body, "application/octet-stream");
               })
        .Delete("/binary",
                [&](const Request &req, Response &res) {
                  EXPECT_EQ(4, req.body.size());
                  EXPECT_EQ("application/octet-stream",
                            req.get_header_value("Content-Type"));
                  EXPECT_EQ("4", req.get_header_value("Content-Length"));
                  res.set_content(req.body, "application/octet-stream");
                })
#if defined(CPPHTTPLIB_ZLIB_SUPPORT) || defined(CPPHTTPLIB_BROTLI_SUPPORT)
        .Get("/compress",
             [&](const Request & /*req*/, Response &res) {
               res.set_content(
                   "12345678901234567890123456789012345678901234567890123456789"
                   "01234567890123456789012345678901234567890",
                   "text/plain");
             })
        .Get("/nocompress",
             [&](const Request & /*req*/, Response &res) {
               res.set_content(
                   "12345678901234567890123456789012345678901234567890123456789"
                   "01234567890123456789012345678901234567890",
                   "application/octet-stream");
             })
        .Post("/compress-multipart",
              [&](const Request &req, Response & /*res*/) {
                EXPECT_EQ(2u, req.files.size());
                ASSERT_TRUE(!req.has_file("???"));

                {
                  const auto &file = req.get_file_value("key1");
                  EXPECT_TRUE(file.filename.empty());
                  EXPECT_EQ("test", file.content);
                }

                {
                  const auto &file = req.get_file_value("key2");
                  EXPECT_TRUE(file.filename.empty());
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
    if (!request_threads_.empty()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      for (auto &t : request_threads_) {
        t.join();
      }
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
  ASSERT_TRUE(res);
  EXPECT_EQ("HTTP/1.1", res->version);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("OK", res->reason);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ(1, res->get_header_value_count("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, GetMethod200withPercentEncoding) {
  auto res = cli_.Get("/%68%69"); // auto res = cli_.Get("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ("HTTP/1.1", res->version);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ(1, res->get_header_value_count("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);
}

TEST_F(ServerTest, GetMethod302) {
  auto res = cli_.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(302, res->status);
  EXPECT_EQ("/hi", res->get_header_value("Location"));
}

TEST_F(ServerTest, GetMethod302Redirect) {
  cli_.set_follow_location(true);
  auto res = cli_.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("Hello World!", res->body);
  EXPECT_EQ("/hi", res->location);
}

TEST_F(ServerTest, GetMethod404) {
  auto res = cli_.Get("/invalid");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, HeadMethod200) {
  auto res = cli_.Head("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, HeadMethod200Static) {
  auto res = cli_.Head("/mount/dir/index.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ(104, std::stoi(res->get_header_value("Content-Length")));
  EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, HeadMethod404) {
  auto res = cli_.Head("/invalid");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
  EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, GetMethodPersonJohn) {
  auto res = cli_.Get("/person/john");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("programmer", res->body);
}

TEST_F(ServerTest, PostMethod1) {
  auto res = cli_.Get("/person/john1");
  ASSERT_TRUE(res);
  ASSERT_EQ(404, res->status);

  res = cli_.Post("/person", "name=john1&note=coder",
                  "application/x-www-form-urlencoded");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  res = cli_.Get("/person/john1");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
  ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PostMethod2) {
  auto res = cli_.Get("/person/john2");
  ASSERT_TRUE(res);
  ASSERT_EQ(404, res->status);

  Params params;
  params.emplace("name", "john2");
  params.emplace("note", "coder");

  res = cli_.Post("/person", params);
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  res = cli_.Get("/person/john2");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
  ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PutMethod3) {
  auto res = cli_.Get("/person/john3");
  ASSERT_TRUE(res);
  ASSERT_EQ(404, res->status);

  Params params;
  params.emplace("name", "john3");
  params.emplace("note", "coder");

  res = cli_.Put("/person", params);
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  res = cli_.Get("/person/john3");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("text/plain", res->get_header_value("Content-Type"));
  ASSERT_EQ("coder", res->body);
}

TEST_F(ServerTest, PostWwwFormUrlEncodedJson) {
  Params params;
  params.emplace("json", JSON_DATA);

  auto res = cli_.Post("/x-www-form-urlencoded-json", params);

  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(JSON_DATA, res->body);
}

TEST_F(ServerTest, PostEmptyContent) {
  auto res = cli_.Post("/empty", "", "text/plain");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("empty", res->body);
}

TEST_F(ServerTest, PostEmptyContentWithNoContentType) {
  auto res = cli_.Post("/empty-no-content-type");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("empty-no-content-type", res->body);
}

TEST_F(ServerTest, PutEmptyContentWithNoContentType) {
  auto res = cli_.Put("/empty-no-content-type");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("empty-no-content-type", res->body);
}

TEST_F(ServerTest, GetMethodDir) {
  auto res = cli_.Get("/dir/");
  ASSERT_TRUE(res);
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
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirTestWithDoubleDots) {
  auto res = cli_.Get("/dir/../dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidPath) {
  auto res = cli_.Get("/dir/../test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir) {
  auto res = cli_.Get("/../www/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDir2) {
  auto res = cli_.Get("/dir/../../www/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodDirMountTest) {
  auto res = cli_.Get("/mount/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodDirMountTestWithDoubleDots) {
  auto res = cli_.Get("/mount/dir/../dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/html", res->get_header_value("Content-Type"));
  EXPECT_EQ("test.html", res->body);
}

TEST_F(ServerTest, GetMethodInvalidMountPath) {
  auto res = cli_.Get("/mount/dir/../test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDirMount) {
  auto res = cli_.Get("/mount/../www2/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, GetMethodOutOfBaseDirMount2) {
  auto res = cli_.Get("/mount/dir/../../www2/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, PostMethod303) {
  auto res = cli_.Post("/1", "body", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(303, res->status);
  EXPECT_EQ("/2", res->get_header_value("Location"));
}

TEST_F(ServerTest, PostMethod303Redirect) {
  cli_.set_follow_location(true);
  auto res = cli_.Post("/1", "body", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("redirected.", res->body);
  EXPECT_EQ("/2", res->location);
}

TEST_F(ServerTest, UserDefinedMIMETypeMapping) {
  auto res = cli_.Get("/dir/test.abcde");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/abcde", res->get_header_value("Content-Type"));
  EXPECT_EQ("abcde", res->body);
}

TEST_F(ServerTest, StaticFileRange) {
  auto res = cli_.Get("/dir/test.abcde", {{make_range_header({{2, 3}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("text/abcde", res->get_header_value("Content-Type"));
  EXPECT_EQ("2", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("cd"), res->body);
}

TEST_F(ServerTest, InvalidBaseDirMount) {
  EXPECT_EQ(false, svr_.set_mount_point("invalid_mount_point", "./www3"));
}

TEST_F(ServerTest, Binary) {
  std::vector<char> binary{0x00, 0x01, 0x02, 0x03};

  auto res = cli_.Post("/binary", binary.data(), binary.size(),
                       "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Put("/binary", binary.data(), binary.size(),
                 "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Patch("/binary", binary.data(), binary.size(),
                   "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Delete("/binary", binary.data(), binary.size(),
                    "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());
}

TEST_F(ServerTest, BinaryString) {
  auto binary = std::string("\x00\x01\x02\x03", 4);

  auto res = cli_.Post("/binary", binary, "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Put("/binary", binary, "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Patch("/binary", binary, "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());

  res = cli_.Delete("/binary", binary, "application/octet-stream");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ(4, res->body.size());
}

TEST_F(ServerTest, EmptyRequest) {
  auto res = cli_.Get("");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Connection, res.error());
}

TEST_F(ServerTest, LongRequest) {
  std::string request;
  for (size_t i = 0; i < 545; i++) {
    request += "/TooLongRequest";
  }
  request += "OK";

  auto res = cli_.Get(request.c_str());

  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, TooLongRequest) {
  std::string request;
  for (size_t i = 0; i < 545; i++) {
    request += "/TooLongRequest";
  }
  request += "_NG";

  auto res = cli_.Get(request.c_str());

  ASSERT_TRUE(res);
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
  auto error = Error::Success;
  auto ret = cli_.send(req, *res, error);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, LongQueryValue) {
  auto res = cli_.Get(LONG_QUERY_URL.c_str());

  ASSERT_TRUE(res);
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
  auto error = Error::Success;
  auto ret = cli_.send(req, *res, error);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncoding) {
  auto res = cli_.Get("/e%6edwith%");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PercentEncodingUnicode) {
  auto res = cli_.Get("/e%u006edwith%");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, InvalidPercentEncoding) {
  auto res = cli_.Get("/%endwith%");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, InvalidPercentEncodingUnicode) {
  auto res = cli_.Get("/%uendwith%");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, EndWithPercentCharacterInQuery) {
  auto res = cli_.Get("/hello?aaa=bbb%");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
}

TEST_F(ServerTest, PlusSignEncoding) {
  auto res = cli_.Get("/a+%2Bb?a %2bb=a %2Bb");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("a +b", res->body);
}

TEST_F(ServerTest, MultipartFormData) {
  MultipartFormDataItems items = {
      {"text1", "text default", "", ""},
      {"text2", "aωb", "", ""},
      {"file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain"},
      {"file2", "{\n  \"world\", true\n}\n", "world.json", "application/json"},
      {"file3", "", "", "application/octet-stream"},
      {"file4", "", "", "   application/json  tmp-string    "}};

  auto res = cli_.Post("/multipart", items);

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, CaseInsensitiveHeaderName) {
  auto res = cli_.Get("/hi");
  ASSERT_TRUE(res);
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
  auto error = Error::Success;
  auto ret = cli_.send(req, *res, error);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GetStreamed2) {
  auto res = cli_.Get("/streamed", {{make_range_header({{2, 3}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("2", res->get_header_value("Content-Length"));
  EXPECT_EQ(std::string("ab"), res->body);
}

TEST_F(ServerTest, GetStreamed) {
  auto res = cli_.Get("/streamed");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(std::string("aaabbb"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRange1) {
  auto res = cli_.Get("/streamed-with-range", {{make_range_header({{3, 5}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("3", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("def"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRange2) {
  auto res = cli_.Get("/streamed-with-range", {{make_range_header({{1, -1}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("bcdefg"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRangeSuffix1) {
  auto res = cli_.Get("/streamed-with-range", {{"Range", "bytes=-3"}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("3", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("efg"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRangeSuffix2) {
  auto res = cli_.Get("/streamed-with-range", {{"Range", "bytes=-9999"}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("7", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("abcdefg"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRangeError) {
  auto res = cli_.Get("/streamed-with-range",
                      {{"Range", "bytes=92233720368547758079223372036854775806-"
                                 "92233720368547758079223372036854775807"}});
  ASSERT_TRUE(res);
  EXPECT_EQ(416, res->status);
}

TEST_F(ServerTest, GetRangeWithMaxLongLength) {
  auto res =
      cli_.Get("/with-range", {{"Range", "bytes=0-9223372036854775807"}});
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("7", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("abcdefg"), res->body);
}

TEST_F(ServerTest, GetStreamedWithRangeMultipart) {
  auto res =
      cli_.Get("/streamed-with-range", {{make_range_header({{1, 2}, {4, 5}})}});
  ASSERT_TRUE(res);
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
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST_F(ServerTest, ClientStop) {
  std::vector<std::thread> threads;
  for (auto i = 0; i < 3; i++) {
    threads.emplace_back(thread([&]() {
      auto res = cli_.Get("/streamed-cancel",
                          [&](const char *, uint64_t) { return true; });
      ASSERT_TRUE(!res);
      EXPECT_TRUE(res.error() == Error::Canceled ||
                  res.error() == Error::Read || res.error() == Error::Write);
    }));
  }

  std::this_thread::sleep_for(std::chrono::seconds(2));
  while (cli_.is_socket_open()) {
    cli_.stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  for (auto &t : threads) {
    t.join();
  }
}

TEST_F(ServerTest, GetWithRange1) {
  auto res = cli_.Get("/with-range", {{make_range_header({{3, 5}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("3", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("def"), res->body);
}

TEST_F(ServerTest, GetWithRange2) {
  auto res = cli_.Get("/with-range", {{make_range_header({{1, -1}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("6", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("bcdefg"), res->body);
}

TEST_F(ServerTest, GetWithRange3) {
  auto res = cli_.Get("/with-range", {{make_range_header({{0, 0}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("1", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("a"), res->body);
}

TEST_F(ServerTest, GetWithRange4) {
  auto res = cli_.Get("/with-range", {{make_range_header({{-1, 2}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("2", res->get_header_value("Content-Length"));
  EXPECT_EQ(true, res->has_header("Content-Range"));
  EXPECT_EQ(std::string("fg"), res->body);
}

TEST_F(ServerTest, GetWithRangeOffsetGreaterThanContent) {
  auto res = cli_.Get("/with-range", {{make_range_header({{10000, 20000}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(416, res->status);
}

TEST_F(ServerTest, GetWithRangeMultipart) {
  auto res = cli_.Get("/with-range", {{make_range_header({{1, 2}, {4, 5}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(206, res->status);
  EXPECT_EQ("269", res->get_header_value("Content-Length"));
  EXPECT_EQ(false, res->has_header("Content-Range"));
  EXPECT_EQ(269, res->body.size());
}

TEST_F(ServerTest, GetWithRangeMultipartOffsetGreaterThanContent) {
  auto res =
      cli_.Get("/with-range", {{make_range_header({{-1, 2}, {10000, 30000}})}});
  ASSERT_TRUE(res);
  EXPECT_EQ(416, res->status);
}

TEST_F(ServerTest, GetStreamedChunked) {
  auto res = cli_.Get("/streamed-chunked");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}

TEST_F(ServerTest, GetStreamedChunked2) {
  auto res = cli_.Get("/streamed-chunked2");
  ASSERT_TRUE(res);
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
  auto error = Error::Success;
  auto ret = cli_.send(req, *res, error);

  ASSERT_TRUE(ret);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GetMethodRemoteAddr) {
  auto res = cli_.Get("/remote_addr");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_TRUE(res->body == "::1" || res->body == "127.0.0.1");
}

TEST_F(ServerTest, HTTPResponseSplitting) {
  auto res = cli_.Get("/http_response_splitting");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, SlowRequest) {
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
  request_threads_.push_back(
      std::thread([=]() { auto res = cli_.Get("/slow"); }));
}

TEST_F(ServerTest, SlowPost) {
  char buffer[64 * 1024];
  memset(buffer, 0x42, sizeof(buffer));

  auto res = cli_.Post(
      "/slowpost", 64 * 1024 * 1024,
      [&](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        auto ret = sink.write(buffer, sizeof(buffer));
        EXPECT_TRUE(ret);
        return true;
      },
      "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, SlowPostFail) {
  char buffer[64 * 1024];
  memset(buffer, 0x42, sizeof(buffer));

  cli_.set_write_timeout(std::chrono::seconds(0));
  auto res = cli_.Post(
      "/slowpost", 64 * 1024 * 1024,
      [&](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        sink.write(buffer, sizeof(buffer));
        return true;
      },
      "text/plain");

  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Write, res.error());
}

TEST_F(ServerTest, Put) {
  auto res = cli_.Put("/put", "PUT", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PutWithContentProvider) {
  auto res = cli_.Put(
      "/put", 3,
      [](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        EXPECT_TRUE(sink.is_writable());
        sink.os << "PUT";
        return true;
      },
      "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PostWithContentProviderAbort) {
  auto res = cli_.Post(
      "/post", 42,
      [](size_t /*offset*/, size_t /*length*/, DataSink & /*sink*/) {
        return false;
      },
      "text/plain");

  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST_F(ServerTest, PutWithContentProviderWithoutLength) {
  auto res = cli_.Put(
      "/put",
      [](size_t /*offset*/, DataSink &sink) {
        EXPECT_TRUE(sink.is_writable());
        sink.os << "PUT";
        sink.done();
        return true;
      },
      "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PostWithContentProviderWithoutLengthAbort) {
  auto res = cli_.Post(
      "/post", [](size_t /*offset*/, DataSink & /*sink*/) { return false; },
      "text/plain");

  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, PutWithContentProviderWithGzip) {
  cli_.set_compress(true);
  auto res = cli_.Put(
      "/put", 3,
      [](size_t /*offset*/, size_t /*length*/, DataSink &sink) {
        EXPECT_TRUE(sink.is_writable());
        sink.os << "PUT";
        return true;
      },
      "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PostWithContentProviderWithGzipAbort) {
  cli_.set_compress(true);
  auto res = cli_.Post(
      "/post", 42,
      [](size_t /*offset*/, size_t /*length*/, DataSink & /*sink*/) {
        return false;
      },
      "text/plain");

  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST_F(ServerTest, PutWithContentProviderWithoutLengthWithGzip) {
  cli_.set_compress(true);
  auto res = cli_.Put(
      "/put",
      [](size_t /*offset*/, DataSink &sink) {
        EXPECT_TRUE(sink.is_writable());
        sink.os << "PUT";
        sink.done();
        return true;
      },
      "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, PostWithContentProviderWithoutLengthWithGzipAbort) {
  cli_.set_compress(true);
  auto res = cli_.Post(
      "/post", [](size_t /*offset*/, DataSink & /*sink*/) { return false; },
      "text/plain");

  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::Canceled, res.error());
}

TEST_F(ServerTest, PutLargeFileWithGzip) {
  cli_.set_compress(true);
  auto res = cli_.Put("/put-large", LARGE_DATA, "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(LARGE_DATA, res->body);
}

TEST_F(ServerTest, PutLargeFileWithGzip2) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  Client cli("https://localhost:1234");
  cli.enable_server_certificate_verification(false);
#else
  Client cli("http://localhost:1234");
#endif
  cli.set_compress(true);

  auto res = cli.Put("/put-large", LARGE_DATA, "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(LARGE_DATA, res->body);
  EXPECT_EQ(101942u, res.get_request_header_value<uint64_t>("Content-Length"));
  EXPECT_EQ("gzip", res.get_request_header_value("Content-Encoding"));
}

TEST_F(ServerTest, PutContentWithDeflate) {
  cli_.set_compress(false);
  Headers headers;
  headers.emplace("Content-Encoding", "deflate");
  // PUT in deflate format:
  auto res = cli_.Put("/put", headers,
                      "\170\234\013\010\015\001\0\001\361\0\372", "text/plain");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PUT", res->body);
}

TEST_F(ServerTest, GetStreamedChunkedWithGzip) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");

  auto res = cli_.Get("/streamed-chunked", headers);
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}

TEST_F(ServerTest, GetStreamedChunkedWithGzip2) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");

  auto res = cli_.Get("/streamed-chunked2", headers);
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}

TEST(GzipDecompressor, ChunkedDecompression) {
  std::string data;
  for (size_t i = 0; i < 32 * 1024; ++i) {
    data.push_back(static_cast<char>('a' + i % 26));
  }

  std::string compressed_data;
  {
    httplib::detail::gzip_compressor compressor;
    bool result = compressor.compress(
        data.data(), data.size(),
        /*last=*/true, [&](const char *data, size_t size) {
          compressed_data.insert(compressed_data.size(), data, size);
          return true;
        });
    ASSERT_TRUE(result);
  }

  std::string decompressed_data;
  {
    httplib::detail::gzip_decompressor decompressor;

    // Chunk size is chosen specificaly to have a decompressed chunk size equal
    // to 16384 bytes 16384 bytes is the size of decompressor output buffer
    size_t chunk_size = 130;
    for (size_t chunk_begin = 0; chunk_begin < compressed_data.size();
         chunk_begin += chunk_size) {
      size_t current_chunk_size =
          std::min(compressed_data.size() - chunk_begin, chunk_size);
      bool result = decompressor.decompress(
          compressed_data.data() + chunk_begin, current_chunk_size,
          [&](const char *data, size_t size) {
            decompressed_data.insert(decompressed_data.size(), data, size);
            return true;
          });
      ASSERT_TRUE(result);
    }
  }
  ASSERT_EQ(data, decompressed_data);
}
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
TEST_F(ServerTest, GetStreamedChunkedWithBrotli) {
  Headers headers;
  headers.emplace("Accept-Encoding", "br");

  auto res = cli_.Get("/streamed-chunked", headers);
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}

TEST_F(ServerTest, GetStreamedChunkedWithBrotli2) {
  Headers headers;
  headers.emplace("Accept-Encoding", "br");

  auto res = cli_.Get("/streamed-chunked2", headers);
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(std::string("123456789"), res->body);
}
#endif

TEST_F(ServerTest, Patch) {
  auto res = cli_.Patch("/patch", "PATCH", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("PATCH", res->body);
}

TEST_F(ServerTest, Delete) {
  auto res = cli_.Delete("/delete");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("DELETE", res->body);
}

TEST_F(ServerTest, DeleteContentReceiver) {
  auto res = cli_.Delete("/delete-body", "content", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("content", res->body);
}

TEST_F(ServerTest, Options) {
  auto res = cli_.Options("*");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("GET, POST, HEAD, OPTIONS", res->get_header_value("Allow"));
  EXPECT_TRUE(res->body.empty());
}

TEST_F(ServerTest, URL) {
  auto res = cli_.Get("/request-target?aaa=bbb&ccc=ddd");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, ArrayParam) {
  auto res = cli_.Get("/array-param?array=value1&array=value2&array=value3");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, NoMultipleHeaders) {
  Headers headers = {{"Content-Length", "5"}};
  auto res = cli_.Post("/validate-no-multiple-headers", headers, "hello",
                       "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PostContentReceiver) {
  auto res = cli_.Post("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res);
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

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PostMulitpartPlusBoundary) {
  MultipartFormDataItems items = {
      {"text1", "text default", "", ""},
      {"text2", "aωb", "", ""},
      {"file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain"},
      {"file2", "{\n  \"world\", true\n}\n", "world.json", "application/json"},
      {"file3", "", "", "application/octet-stream"},
  };

  auto boundary = std::string("+++++");

  std::string body;

  for (const auto &item : items) {
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"" + item.name + "\"";
    if (!item.filename.empty()) {
      body += "; filename=\"" + item.filename + "\"";
    }
    body += "\r\n";
    if (!item.content_type.empty()) {
      body += "Content-Type: " + item.content_type + "\r\n";
    }
    body += "\r\n";
    body += item.content + "\r\n";
  }
  body += "--" + boundary + "--\r\n";

  std::string content_type = "multipart/form-data; boundary=" + boundary;
  auto res = cli_.Post("/content_receiver", body, content_type.c_str());

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, PostContentReceiverGzip) {
  cli_.set_compress(true);
  auto res = cli_.Post("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PutContentReceiver) {
  auto res = cli_.Put("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PatchContentReceiver) {
  auto res = cli_.Patch("/content_receiver", "content", "text/plain");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
  ASSERT_EQ("content", res->body);
}

TEST_F(ServerTest, PostQueryStringAndBody) {
  auto res =
      cli_.Post("/query-string-and-body?key=value", "content", "text/plain");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
}

TEST_F(ServerTest, HTTP2Magic) {
  Request req;
  req.method = "PRI";
  req.path = "*";
  req.body = "SM";

  auto res = std::make_shared<Response>();
  auto error = Error::Success;
  auto ret = cli_.send(req, *res, error);

  ASSERT_TRUE(ret);
  EXPECT_EQ(400, res->status);
}

TEST_F(ServerTest, KeepAlive) {
  auto res = cli_.Get("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);

  res = cli_.Get("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);

  res = cli_.Get("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("Hello World!", res->body);

  res = cli_.Get("/not-exist");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);

  res = cli_.Post("/empty", "", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("empty", res->body);
  EXPECT_EQ("close", res->get_header_value("Connection"));

  res = cli_.Post(
      "/empty", 0, [&](size_t, size_t, DataSink &) { return true; },
      "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("empty", res->body);

  cli_.set_keep_alive(false);
  res = cli_.Get("/last-request");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("close", res->get_header_value("Connection"));
}

TEST_F(ServerTest, TooManyRedirect) {
  cli_.set_follow_location(true);
  auto res = cli_.Get("/redirect/0");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::ExceedRedirectCount, res.error());
}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
TEST_F(ServerTest, Gzip) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");
  auto res = cli_.Get("/compress", headers);

  ASSERT_TRUE(res);
  EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("33", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            res->body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithoutAcceptEncoding) {
  auto res = cli_.Get("/compress");

  ASSERT_TRUE(res);
  EXPECT_TRUE(res->get_header_value("Content-Encoding").empty());
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
  auto res = cli_.Get("/compress", headers,
                      [&](const char *data, uint64_t data_length) {
                        EXPECT_EQ(data_length, 100);
                        body.append(data, data_length);
                        return true;
                      });

  ASSERT_TRUE(res);
  EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("33", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            body);
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithoutDecompressing) {
  Headers headers;
  headers.emplace("Accept-Encoding", "gzip, deflate");

  cli_.set_decompress(false);
  auto res = cli_.Get("/compress", headers);

  ASSERT_TRUE(res);
  EXPECT_EQ("gzip", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("33", res->get_header_value("Content-Length"));
  EXPECT_EQ(33, res->body.size());
  EXPECT_EQ(200, res->status);
}

TEST_F(ServerTest, GzipWithContentReceiverWithoutAcceptEncoding) {
  std::string body;
  auto res = cli_.Get("/compress", [&](const char *data, uint64_t data_length) {
    EXPECT_EQ(data_length, 100);
    body.append(data, data_length);
    return true;
  });

  ASSERT_TRUE(res);
  EXPECT_TRUE(res->get_header_value("Content-Encoding").empty());
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
  auto res = cli_.Get("/nocompress", headers);

  ASSERT_TRUE(res);
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
  auto res = cli_.Get("/nocompress", headers,
                      [&](const char *data, uint64_t data_length) {
                        EXPECT_EQ(data_length, 100);
                        body.append(data, data_length);
                        return true;
                      });

  ASSERT_TRUE(res);
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
  auto res = cli_.Post("/compress-multipart", items);

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}
#endif

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
TEST_F(ServerTest, Brotli) {
  Headers headers;
  headers.emplace("Accept-Encoding", "br");
  auto res = cli_.Get("/compress", headers);

  ASSERT_TRUE(res);
  EXPECT_EQ("br", res->get_header_value("Content-Encoding"));
  EXPECT_EQ("text/plain", res->get_header_value("Content-Type"));
  EXPECT_EQ("19", res->get_header_value("Content-Length"));
  EXPECT_EQ("123456789012345678901234567890123456789012345678901234567890123456"
            "7890123456789012345678901234567890",
            res->body);
  EXPECT_EQ(200, res->status);
}
#endif

// Sends a raw request to a server listening at HOST:PORT.
static bool send_request(time_t read_timeout_sec, const std::string &req,
                         std::string *resp = nullptr) {
  auto error = Error::Success;

  auto client_sock = detail::create_client_socket(
      HOST, PORT, AF_UNSPEC, false, nullptr,
      /*connection_timeout_sec=*/5, 0,
      /*read_timeout_sec=*/5, 0,
      /*write_timeout_sec=*/5, 0, std::string(), error);

  if (client_sock == INVALID_SOCKET) { return false; }

  auto ret = detail::process_client_socket(
      client_sock, read_timeout_sec, 0, 0, 0, [&](Stream &strm) {
        if (req.size() !=
            static_cast<size_t>(strm.write(req.data(), req.size()))) {
          return false;
        }

        char buf[512];

        detail::stream_line_reader line_reader(strm, buf, sizeof(buf));
        while (line_reader.getline()) {
          if (resp) { *resp += line_reader.ptr(); }
        }
        return true;
      });

  detail::close_socket(client_sock);

  return ret;
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
static void test_raw_request(const std::string &req,
                             std::string *out = nullptr) {
  Server svr;
  svr.Get("/hi", [&](const Request & /*req*/, Response &res) {
    res.set_content("ok", "text/plain");
  });
  svr.Put("/put_hi", [&](const Request & /*req*/, Response &res) {
    res.set_content("ok", "text/plain");
  });

  // Server read timeout must be longer than the client read timeout for the
  // bug to reproduce, probably to force the server to process a request
  // without a trailing blank line.
  const time_t client_read_timeout_sec = 1;
  svr.set_read_timeout(std::chrono::seconds(client_read_timeout_sec + 1));
  bool listen_thread_ok = false;
  thread t = thread([&] { listen_thread_ok = svr.listen(HOST, PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  ASSERT_TRUE(send_request(client_read_timeout_sec, req, out));
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
      "                                                                      "
      " ");
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

TEST(ServerRequestParsingTest, ExcessiveWhitespaceInUnparseableHeaderLine) {
  // Make sure this doesn't crash the server.
  // In a previous version of the header line regex, the "\r" rendered the line
  // unparseable and the regex engine repeatedly backtracked, trying to look for
  // a new position where the leading white space ended and the field value
  // began.
  // The crash occurs with libc++ but not libstdc++.
  test_raw_request("GET /hi HTTP/1.1\r\n"
                   "a:" +
                   std::string(2000, ' ') + '\r' + std::string(20, 'z') +
                   "\r\n"
                   "\r\n");
}

TEST(ServerRequestParsingTest, InvalidFirstChunkLengthInRequest) {
  std::string out;

  test_raw_request("PUT /put_hi HTTP/1.1\r\n"
                   "Content-Type: text/plain\r\n"
                   "Transfer-Encoding: chunked\r\n"
                   "\r\n"
                   "nothex\r\n",
                   &out);
  EXPECT_EQ("HTTP/1.1 400 Bad Request", out.substr(0, 24));
}

TEST(ServerRequestParsingTest, InvalidSecondChunkLengthInRequest) {
  std::string out;

  test_raw_request("PUT /put_hi HTTP/1.1\r\n"
                   "Content-Type: text/plain\r\n"
                   "Transfer-Encoding: chunked\r\n"
                   "\r\n"
                   "3\r\n"
                   "xyz\r\n"
                   "NaN\r\n",
                   &out);
  EXPECT_EQ("HTTP/1.1 400 Bad Request", out.substr(0, 24));
}

TEST(ServerRequestParsingTest, ChunkLengthTooHighInRequest) {
  std::string out;

  test_raw_request("PUT /put_hi HTTP/1.1\r\n"
                   "Content-Type: text/plain\r\n"
                   "Transfer-Encoding: chunked\r\n"
                   "\r\n"
                   // Length is too large for 64 bits.
                   "1ffffffffffffffff\r\n"
                   "xyz\r\n",
                   &out);
  EXPECT_EQ("HTTP/1.1 400 Bad Request", out.substr(0, 24));
}

TEST(ServerRequestParsingTest, InvalidHeaderTextWithExtraCR) {
  test_raw_request("GET /hi HTTP/1.1\r\n"
                   "Content-Type: text/plain\r\n\r");
}

TEST(ServerRequestParsingTest, InvalidSpaceInURL) {
  std::string out;
  test_raw_request("GET /h i HTTP/1.1\r\n\r\n", &out);
  EXPECT_EQ("HTTP/1.1 400 Bad Request", out.substr(0, 24));
}

TEST(ServerStopTest, StopServerWithChunkedTransmission) {
  Server svr;

  svr.Get("/events", [](const Request & /*req*/, Response &res) {
    res.set_header("Cache-Control", "no-cache");
    res.set_chunked_content_provider("text/event-stream", [](size_t offset,
                                                             DataSink &sink) {
      char buffer[27];
      auto size = static_cast<size_t>(sprintf(buffer, "data:%ld\n\n", offset));
      auto ret = sink.write(buffer, size);
      EXPECT_TRUE(ret);
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    });
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  Client client(HOST, PORT);
  const Headers headers = {{"Accept", "text/event-stream"}};

  auto get_thread = std::thread([&client, &headers]() {
    auto res = client.Get(
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

TEST(StreamingTest, NoContentLengthStreaming) {
  Server svr;

  svr.Get("/stream", [](const Request & /*req*/, Response &res) {
    res.set_content_provider("text/plain", [](size_t offset, DataSink &sink) {
      if (offset < 6) {
        sink.os << (offset < 3 ? "a" : "b");
      } else {
        sink.done();
      }
      return true;
    });
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  Client client(HOST, PORT);

  auto get_thread = std::thread([&client]() {
    auto res = client.Get("/stream", [](const char *data, size_t len) -> bool {
      EXPECT_EQ("aaabbb", std::string(data, len));
      return true;
    });
  });

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

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
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);

  res = cli.Get("/mount2/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);

  svr.set_mount_point("/", "./www");

  res = cli.Get("/dir/");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);

  svr.remove_mount_point("/");
  res = cli.Get("/dir/");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);

  svr.remove_mount_point("/mount2");
  res = cli.Get("/mount2/dir/test.html");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(ExceptionTest, ThrowExceptionInHandler) {
  Server svr;

  svr.Get("/hi", [&](const Request & /*req*/, Response & /*res*/) {
    throw std::runtime_error("exception...");
    // res.set_content("Hello World!", "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  auto res = cli.Get("/hi");
  ASSERT_TRUE(res);
  EXPECT_EQ(500, res->status);
  ASSERT_TRUE(res->has_header("EXCEPTION_WHAT"));
  EXPECT_EQ("exception...", res->get_header_value("EXCEPTION_WHAT"));

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(KeepAliveTest, ReadTimeout) {
  Server svr;

  svr.Get("/a", [&](const Request & /*req*/, Response &res) {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    res.set_content("a", "text/plain");
  });

  svr.Get("/b", [&](const Request & /*req*/, Response &res) {
    res.set_content("b", "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);
  cli.set_keep_alive(true);
  cli.set_read_timeout(std::chrono::seconds(1));

  auto resa = cli.Get("/a");
  ASSERT_TRUE(!resa);
  EXPECT_EQ(Error::Read, resa.error());

  auto resb = cli.Get("/b");
  ASSERT_TRUE(resb);
  EXPECT_EQ(200, resb->status);
  EXPECT_EQ("b", resb->body);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(ClientProblemDetectionTest, ContentProvider) {
  Server svr;

  size_t content_length = 1024 * 1024;

  svr.Get("/hi", [&](const Request & /*req*/, Response &res) {
    res.set_content_provider(
        content_length, "text/plain",
        [&](size_t offset, size_t length, DataSink &sink) {
          auto out_len = std::min(length, static_cast<size_t>(1024));
          std::string out(out_len, '@');
          sink.write(out.data(), out_len);
          return offset < 4096;
        },
        [](bool success) { ASSERT_FALSE(success); });
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  auto res = cli.Get("/hi", [&](const char * /*data*/, size_t /*data_length*/) {
    return false;
  });

  ASSERT_FALSE(res);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(ErrorHandlerWithContentProviderTest, ErrorHandler) {
  Server svr;

  svr.set_error_handler([](Request const &, Response &res) -> void {
    res.set_chunked_content_provider(
        "text/plain", [](std::size_t const, DataSink &sink) -> bool {
          sink.os << "hello";
          sink.os << "world";
          sink.done();
          return true;
        });
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(404, res->status);
  EXPECT_EQ("helloworld", res->body);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(GetWithParametersTest, GetWithParameters) {
  Server svr;

  svr.Get("/", [&](const Request &req, Response &res) {
    auto text = req.get_param_value("hello");
    res.set_content(text, "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  Params params;
  params.emplace("hello", "world");
  auto res = cli.Get("/", params, Headers{});

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("world", res->body);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(GetWithParametersTest, GetWithParameters2) {
  Server svr;

  svr.Get("/", [&](const Request &req, Response &res) {
    auto text = req.get_param_value("hello");
    res.set_content(text, "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  Params params;
  params.emplace("hello", "world");

  std::string body;
  auto res = cli.Get("/", params, Headers{},
                     [&](const char *data, size_t data_length) {
                       body.append(data, data_length);
                       return true;
                     });

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("world", body);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

TEST(ClientDefaultHeadersTest, DefaultHeaders) {
  Client cli("httpbin.org");
  cli.set_default_headers({make_range_header({{1, 10}})});
  cli.set_connection_timeout(5);

  {
    auto res = cli.Get("/range/32");
    ASSERT_TRUE(res);
    EXPECT_EQ("bcdefghijk", res->body);
    EXPECT_EQ(206, res->status);
  }

  {
    auto res = cli.Get("/range/32");
    ASSERT_TRUE(res);
    EXPECT_EQ("bcdefghijk", res->body);
    EXPECT_EQ(206, res->status);
  }
}

TEST(ServerDefaultHeadersTest, DefaultHeaders) {
  Server svr;
  svr.set_default_headers({{"Hello", "World"}});

  svr.Get("/", [&](const Request & /*req*/, Response &res) {
    res.set_content("ok", "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  std::this_thread::sleep_for(std::chrono::seconds(1));

  Client cli("localhost", PORT);

  auto res = cli.Get("/");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("ok", res->body);
  EXPECT_EQ("World", res->get_header_value("Hello"));

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(KeepAliveTest, ReadTimeoutSSL) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/a", [&](const Request & /*req*/, Response &res) {
    std::this_thread::sleep_for(std::chrono::seconds(2));
    res.set_content("a", "text/plain");
  });

  svr.Get("/b", [&](const Request & /*req*/, Response &res) {
    res.set_content("b", "text/plain");
  });

  auto listen_thread = std::thread([&svr]() { svr.listen("localhost", PORT); });
  while (!svr.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // Give GET time to get a few messages.
  std::this_thread::sleep_for(std::chrono::seconds(1));

  SSLClient cli("localhost", PORT);
  cli.enable_server_certificate_verification(false);
  cli.set_keep_alive(true);
  cli.set_read_timeout(std::chrono::seconds(1));

  auto resa = cli.Get("/a");
  ASSERT_TRUE(!resa);
  EXPECT_EQ(Error::Read, resa.error());

  auto resb = cli.Get("/b");
  ASSERT_TRUE(resb);
  EXPECT_EQ(200, resb->status);
  EXPECT_EQ("b", resb->body);

  svr.stop();
  listen_thread.join();
  ASSERT_FALSE(svr.is_running());
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    cli_.enable_server_certificate_verification(false);
#endif
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
  ASSERT_TRUE(res);
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    cli_.enable_server_certificate_verification(false);
#endif
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
  ASSERT_TRUE(res);
  EXPECT_EQ(413, res->status);

  res = cli_.Post("/test", "12345678", "text/plain");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(SSLClientTest, UpdateCAStore) {
  httplib::SSLClient httplib_client("www.google.com");
  auto ca_store_1 = X509_STORE_new();
  X509_STORE_load_locations(ca_store_1, "/etc/ssl/certs/ca-certificates.crt",
                            nullptr);
  httplib_client.set_ca_cert_store(ca_store_1);

  auto ca_store_2 = X509_STORE_new();
  X509_STORE_load_locations(ca_store_2, "/etc/ssl/certs/ca-certificates.crt",
                            nullptr);
  httplib_client.set_ca_cert_store(ca_store_2);
}

TEST(SSLClientTest, ServerNameIndication) {
  SSLClient cli("httpbin.org", 443);
  auto res = cli.Get("/get");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);
}

TEST(SSLClientTest, ServerCertificateVerification1) {
  SSLClient cli("google.com");
  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  ASSERT_EQ(301, res->status);
}

TEST(SSLClientTest, ServerCertificateVerification2) {
  SSLClient cli("google.com");
  cli.enable_server_certificate_verification(true);
  cli.set_ca_cert_path("hello");
  auto res = cli.Get("/");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::SSLLoadingCerts, res.error());
}

TEST(SSLClientTest, ServerCertificateVerification3) {
  SSLClient cli("google.com");
  cli.set_ca_cert_path(CA_CERT_FILE);
  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  ASSERT_EQ(301, res->status);
}

TEST(SSLClientTest, ServerCertificateVerification4) {
  SSLServer svr(SERVER_CERT2_FILE, SERVER_PRIVATE_KEY_FILE);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &, Response &res) {
    res.set_content("test", "text/plain");
    svr.stop();
    ASSERT_TRUE(true);
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen("127.0.0.1", PORT)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  SSLClient cli("127.0.0.1", PORT);
  cli.set_ca_cert_path(SERVER_CERT2_FILE);
  cli.enable_server_certificate_verification(true);
  cli.set_connection_timeout(30);

  auto res = cli.Get("/test");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  t.join();
}

TEST(SSLClientTest, WildcardHostNameMatch) {
  SSLClient cli("www.youtube.com");

  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.enable_server_certificate_verification(true);
  cli.set_follow_location(true);

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
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
      common_name.assign(name, static_cast<size_t>(name_len));
    }

    EXPECT_EQ("Common Name", common_name);

    X509_free(peer_cert);
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  SSLClient cli(HOST, PORT, CLIENT_CERT_FILE, CLIENT_PRIVATE_KEY_FILE);
  cli.enable_server_certificate_verification(false);
  cli.set_connection_timeout(30);

  auto res = cli.Get("/test");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  t.join();
}

#if !defined(_WIN32) || defined(OPENSSL_USE_APPLINK)
TEST(SSLClientServerTest, MemoryClientCertPresent) {
  X509 *server_cert;
  EVP_PKEY *server_private_key;
  X509_STORE *client_ca_cert_store;
  X509 *client_cert;
  EVP_PKEY *client_private_key;

  FILE *f = fopen(SERVER_CERT_FILE, "r+");
  server_cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
  fclose(f);

  f = fopen(SERVER_PRIVATE_KEY_FILE, "r+");
  server_private_key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  fclose(f);

  f = fopen(CLIENT_CA_CERT_FILE, "r+");
  client_cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
  client_ca_cert_store = X509_STORE_new();
  X509_STORE_add_cert(client_ca_cert_store, client_cert);
  X509_free(client_cert);
  fclose(f);

  f = fopen(CLIENT_CERT_FILE, "r+");
  client_cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
  fclose(f);

  f = fopen(CLIENT_PRIVATE_KEY_FILE, "r+");
  client_private_key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  fclose(f);

  SSLServer svr(server_cert, server_private_key, client_ca_cert_store);
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
      common_name.assign(name, static_cast<size_t>(name_len));
    }

    EXPECT_EQ("Common Name", common_name);

    X509_free(peer_cert);
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  SSLClient cli(HOST, PORT, client_cert, client_private_key);
  cli.enable_server_certificate_verification(false);
  cli.set_connection_timeout(30);

  auto res = cli.Get("/test");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  X509_free(server_cert);
  EVP_PKEY_free(server_private_key);
  X509_free(client_cert);
  EVP_PKEY_free(client_private_key);

  t.join();
}
#endif

TEST(SSLClientServerTest, ClientCertMissing) {
  SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE, CLIENT_CA_CERT_FILE,
                CLIENT_CA_CERT_DIR);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &, Response &) { ASSERT_TRUE(false); });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  SSLClient cli(HOST, PORT);
  auto res = cli.Get("/test");
  cli.set_connection_timeout(30);
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::SSLServerVerification, res.error());

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

  SSLClient cli(HOST, PORT, CLIENT_CERT_FILE, CLIENT_PRIVATE_KEY_FILE);
  cli.enable_server_certificate_verification(false);
  cli.set_connection_timeout(30);

  auto res = cli.Get("/test");
  ASSERT_TRUE(res);
  ASSERT_EQ(200, res->status);

  t.join();
}

TEST(SSLClientServerTest, SSLConnectTimeout) {
  class NoListenSSLServer : public SSLServer {
  public:
    NoListenSSLServer(const char *cert_path, const char *private_key_path,
                      const char *client_ca_cert_file_path,
                      const char *client_ca_cert_dir_path = nullptr)
        : SSLServer(cert_path, private_key_path, client_ca_cert_file_path,
                    client_ca_cert_dir_path),
          stop_(false) {}

    bool stop_;

  private:
    bool process_and_close_socket(socket_t /*sock*/) override {
      // Don't create SSL context
      while (!stop_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      return true;
    }
  };
  NoListenSSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE,
                        CLIENT_CA_CERT_FILE);
  ASSERT_TRUE(svr.is_valid());

  svr.Get("/test", [&](const Request &, Response &res) {
    res.set_content("test", "text/plain");
  });

  thread t = thread([&]() { ASSERT_TRUE(svr.listen(HOST, PORT)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(1));

  SSLClient cli(HOST, PORT, CLIENT_CERT_FILE, CLIENT_PRIVATE_KEY_FILE);
  cli.enable_server_certificate_verification(false);
  cli.set_connection_timeout(1);

  auto res = cli.Get("/test");
  ASSERT_TRUE(!res);
  EXPECT_EQ(Error::SSLConnection, res.error());

  svr.stop_ = true;
  svr.stop();
  t.join();
}
#endif

#ifdef _WIN32
TEST(CleanupTest, WSACleanup) {
  int ret = WSACleanup();
  ASSERT_EQ(0, ret);
}
#endif

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(NoSSLSupport, SimpleInterface) {
  ASSERT_ANY_THROW(Client cli("https://yahoo.com"));
}
#endif

TEST(InvalidScheme, SimpleInterface) {
  ASSERT_ANY_THROW(Client cli("scheme://yahoo.com"));
}

TEST(NoScheme, SimpleInterface) {
  Client cli("yahoo.com:80");
  ASSERT_TRUE(cli.is_valid());
}

TEST(SendAPI, SimpleInterface) {
  Client cli("http://yahoo.com");

  Request req;
  req.method = "GET";
  req.path = "/";
  auto res = cli.send(req);

  ASSERT_TRUE(res);
  EXPECT_EQ(301, res->status);
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
TEST(YahooRedirectTest2, SimpleInterface) {
  Client cli("http://yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(301, res->status);

  cli.set_follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("https://yahoo.com/", res->location);
}

TEST(YahooRedirectTest3, SimpleInterface) {
  Client cli("https://yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(301, res->status);

  cli.set_follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("https://www.yahoo.com/", res->location);
}

TEST(YahooRedirectTest3, NewResultInterface) {
  Client cli("https://yahoo.com");

  auto res = cli.Get("/");
  ASSERT_TRUE(res);
  ASSERT_FALSE(!res);
  ASSERT_TRUE(res);
  ASSERT_FALSE(res == nullptr);
  ASSERT_TRUE(res != nullptr);
  EXPECT_EQ(Error::Success, res.error());
  EXPECT_EQ(301, res.value().status);
  EXPECT_EQ(301, (*res).status);
  EXPECT_EQ(301, res->status);

  cli.set_follow_location(true);
  res = cli.Get("/");
  ASSERT_TRUE(res);
  EXPECT_EQ(Error::Success, res.error());
  EXPECT_EQ(200, res.value().status);
  EXPECT_EQ(200, (*res).status);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ("https://www.yahoo.com/", res->location);
}

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
TEST(DecodeWithChunkedEncoding, BrotliEncoding) {
  Client cli("https://cdnjs.cloudflare.com");
  auto res =
      cli.Get("/ajax/libs/jquery/3.5.1/jquery.js", {{"Accept-Encoding", "br"}});

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
  EXPECT_EQ(287630, res->body.size());
  EXPECT_EQ("application/javascript; charset=utf-8",
            res->get_header_value("Content-Type"));
}
#endif

TEST(HttpsToHttpRedirectTest, SimpleInterface) {
  Client cli("https://nghttp2.org");
  cli.set_follow_location(true);
  auto res =
      cli.Get("/httpbin/"
              "redirect-to?url=http%3A%2F%2Fwww.google.com&status_code=302");

  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest2, SimpleInterface) {
  Client cli("https://nghttp2.org");
  cli.set_follow_location(true);

  Params params;
  params.emplace("url", "http://www.google.com");
  params.emplace("status_code", "302");

  auto res = cli.Get("/httpbin/redirect-to", params, Headers{});
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}

TEST(HttpsToHttpRedirectTest3, SimpleInterface) {
  Client cli("https://nghttp2.org");
  cli.set_follow_location(true);

  Params params;
  params.emplace("url", "http://www.google.com");

  auto res = cli.Get("/httpbin/redirect-to?status_code=302", params, Headers{});
  ASSERT_TRUE(res);
  EXPECT_EQ(200, res->status);
}
#endif
