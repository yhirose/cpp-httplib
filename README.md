cpp-httplib
===========

[![](https://github.com/yhirose/cpp-httplib/workflows/test/badge.svg)](https://github.com/yhirose/cpp-httplib/actions)
[![Build Status](https://travis-ci.org/yhirose/cpp-httplib.svg?branch=master)](https://travis-ci.org/yhirose/cpp-httplib)
[![Bulid Status](https://ci.appveyor.com/api/projects/status/github/yhirose/cpp-httplib?branch=master&svg=true)](https://ci.appveyor.com/project/yhirose/cpp-httplib)

A C++11 single-file header-only cross platform HTTP/HTTPS library.

It's extremely easy to setup. Just include **httplib.h** file in your code!

Server Example
--------------

```c++
#include <httplib.h>

int main(void)
{
    using namespace httplib;

    Server svr;

    svr.Get("/hi", [](const Request& req, Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    svr.Get(R"(/numbers/(\d+))", [&](const Request& req, Response& res) {
        auto numbers = req.matches[1];
        res.set_content(numbers, "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        svr.stop();
    });

    svr.listen("localhost", 1234);
}
```

`Post`, `Put`, `Delete` and `Options` methods are also supported.

### Bind a socket to multiple interfaces and any available port

```cpp
int port = svr.bind_to_any_port("0.0.0.0");
svr.listen_after_bind();
```

### Static File Server

```cpp
// Mount / to ./www directory
auto ret = svr.set_mount_point("/", "./www");
if (!ret) {
  // The specified base directory doesn't exist...
}

// Mount /public to ./www directory
ret = svr.set_mount_point("/public", "./www");

// Mount /public to ./www1 and ./www2 directories
ret = svr.set_mount_point("/public", "./www1"); // 1st order to search
ret = svr.set_mount_point("/public", "./www2"); // 2nd order to search

// Remove mount /
ret = svr.remove_mount_point("/");

// Remove mount /public
ret = svr.remove_mount_point("/public");
```

```cpp
// User defined file extension and MIME type mappings
svr.set_file_extension_and_mimetype_mapping("cc", "text/x-c");
svr.set_file_extension_and_mimetype_mapping("cpp", "text/x-c");
svr.set_file_extension_and_mimetype_mapping("hh", "text/x-h");
```

The followings are built-in mappings:

| Extension |     MIME Type          |
| :-------- | :--------------------- |
| txt       | text/plain             |
| html, htm | text/html              |
| css       | text/css               |
| jpeg, jpg | image/jpg              |
| png       | image/png              |
| gif       | image/gif              |
| svg       | image/svg+xml          |
| ico       | image/x-icon           |
| json      | application/json       |
| pdf       | application/pdf        |
| js        | application/javascript |
| wasm      | application/wasm       |
| xml       | application/xml        |
| xhtml     | application/xhtml+xml  |

NOTE: These the static file server methods are not thread safe.

### Logging

```cpp
svr.set_logger([](const auto& req, const auto& res) {
    your_logger(req, res);
});
```

### Error handler

```cpp
svr.set_error_handler([](const auto& req, auto& res) {
    auto fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
    char buf[BUFSIZ];
    snprintf(buf, sizeof(buf), fmt, res.status);
    res.set_content(buf, "text/html");
});
```

### 'multipart/form-data' POST data

```cpp
svr.Post("/multipart", [&](const auto& req, auto& res) {
    auto size = req.files.size();
    auto ret = req.has_file("name1");
    const auto& file = req.get_file_value("name1");
    // file.filename;
    // file.content_type;
    // file.content;
});

```

### Send content with Content provider

```cpp
const uint64_t DATA_CHUNK_SIZE = 4;

svr.Get("/stream", [&](const Request &req, Response &res) {
  auto data = new std::string("abcdefg");

  res.set_content_provider(
    data->size(), // Content length
    [data](uint64_t offset, uint64_t length, DataSink &sink) {
      const auto &d = *data;
      sink.write(&d[offset], std::min(length, DATA_CHUNK_SIZE));
    },
    [data] { delete data; });
});
```

### Receive content with Content receiver

```cpp
svr.Post("/content_receiver",
  [&](const Request &req, Response &res, const ContentReader &content_reader) {
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
    } else {
      std::string body;
      content_reader([&](const char *data, size_t data_length) {
        body.append(data, data_length);
        return true;
      });
      res.set_content(body, "text/plain");
    }
  });
```

### Chunked transfer encoding

```cpp
svr.Get("/chunked", [&](const Request& req, Response& res) {
  res.set_chunked_content_provider(
    [](uint64_t offset, DataSink &sink) {
       sink.write("123", 3);
       sink.write("345", 3);
       sink.write("789", 3);
       sink.done();
    }
  );
});
```

### Server-Sent Events

Please check [here](https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc).

### Default thread pool support


`ThreadPool` is used as a default task queue, and the default thread count is set to value from `std::thread::hardware_concurrency()`.

Set thread count to 8:

```cpp
#define CPPHTTPLIB_THREAD_POOL_COUNT 8
```

### Override the default thread pool with yours

```cpp
class YourThreadPoolTaskQueue : public TaskQueue {
public:
  YourThreadPoolTaskQueue(size_t n) {
    pool_.start_with_thread_count(n);
  }

  virtual void enqueue(std::function<void()> fn) override {
    pool_.enqueue(fn);
  }

  virtual void shutdown() override {
    pool_.shutdown_gracefully();
  }

private:
  YourThreadPool pool_;
};

svr.new_task_queue = [] {
  return new YourThreadPoolTaskQueue(12);
};
```

### 'Expect: 100-continue' handler

As default, the server sends `100 Continue` response for `Expect: 100-continue` header.

```cpp
// Send a '417 Expectation Failed' response.
svr.set_expect_100_continue_handler([](const Request &req, Response &res) {
  return 417;
});
```

```cpp
// Send a final status without reading the message body.
svr.set_expect_100_continue_handler([](const Request &req, Response &res) {
  return res.status = 401;
});
```

Client Example
--------------

### GET

```c++
#include <httplib.h>
#include <iostream>

int main(void)
{
    httplib::Client cli("localhost", 1234);

    auto res = cli.Get("/hi");
    if (res && res->status == 200) {
        std::cout << res->body << std::endl;
    }
}
```

### GET with HTTP headers

```c++
  httplib::Headers headers = {
    { "Accept-Encoding", "gzip, deflate" }
  };
  auto res = cli.Get("/hi", headers);
```

### GET with Content Receiver

```c++
  std::string body;

  auto res = cli.Get("/large-data",
    [&](const char *data, uint64_t data_length) {
      body.append(data, data_length);
      return true;
    });

  assert(res->body.empty());
```

### POST

```c++
res = cli.Post("/post", "text", "text/plain");
res = cli.Post("/person", "name=john1&note=coder", "application/x-www-form-urlencoded");
```

### POST with parameters

```c++
httplib::Params params;
params.emplace("name", "john");
params.emplace("note", "coder");

auto res = cli.Post("/post", params);
```
 or

```c++
httplib::Params params{
  { "name", "john" },
  { "note", "coder" }
};

auto res = cli.Post("/post", params);
```

### POST with Multipart Form Data

```c++
  httplib::MultipartFormDataItems items = {
    { "text1", "text default", "", "" },
    { "text2", "aωb", "", "" },
    { "file1", "h\ne\n\nl\nl\no\n", "hello.txt", "text/plain" },
    { "file2", "{\n  \"world\", true\n}\n", "world.json", "application/json" },
    { "file3", "", "", "application/octet-stream" },
  };

  auto res = cli.Post("/multipart", items);
```

### PUT

```c++
res = cli.Put("/resource/foo", "text", "text/plain");
```

### DELETE

```c++
res = cli.Delete("/resource/foo");
```

### OPTIONS

```c++
res = cli.Options("*");
res = cli.Options("/resource/foo");
```

### Connection Timeout

```c++
cli.set_timeout_sec(5); // timeouts in 5 seconds
```
### With Progress Callback

```cpp
httplib::Client client(url, port);

// prints: 0 / 000 bytes => 50% complete
std::shared_ptr<httplib::Response> res =
    cli.Get("/", [](uint64_t len, uint64_t total) {
        printf("%lld / %lld bytes => %d%% complete\n",
            len, total,
            (int)((len/total)*100));
        return true; // return 'false' if you want to cancel the request.
    }
);
```

![progress](https://user-images.githubusercontent.com/236374/33138910-495c4ecc-cf86-11e7-8693-2fc6d09615c4.gif)

### Authentication

```cpp
// Basic Authentication
cli.set_basic_auth("user", "pass");

// Digest Authentication
cli.set_digest_auth("user", "pass");
```

NOTE: OpenSSL is required for Digest Authentication.

### Proxy server support

```cpp
cli.set_proxy("host", port);

// Basic Authentication
cli.set_proxy_basic_auth("user", "pass");

// Digest Authentication
cli.set_proxy_digest_auth("user", "pass");
```

NOTE: OpenSSL is required for Digest Authentication.

### Range

```cpp
httplib::Client cli("httpbin.org");

auto res = cli.Get("/range/32", {
  httplib::make_range_header({{1, 10}}) // 'Range: bytes=1-10'
});
// res->status should be 206.
// res->body should be "bcdefghijk".
```

```cpp
httplib::make_range_header({{1, 10}, {20, -1}})      // 'Range: bytes=1-10, 20-'
httplib::make_range_header({{100, 199}, {500, 599}}) // 'Range: bytes=100-199, 500-599'
httplib::make_range_header({{0, 0}, {-1, 1}})        // 'Range: bytes=0-0, -1'
```

### Keep-Alive connection

```cpp
cli.set_keep_alive_max_count(2); // Default is 5

std::vector<Request> requests;
Get(requests, "/get-request1");
Get(requests, "/get-request2");
Post(requests, "/post-request1", "text", "text/plain");
Post(requests, "/post-request2", "text", "text/plain");

std::vector<Response> responses;
if (cli.send(requests, responses)) {
  for (const auto& res: responses) {
    ...
  }
}
```

### Redirect

```cpp
httplib::Client cli("yahoo.com");

auto res = cli.Get("/");
res->status; // 301

cli.set_follow_location(true);
res = cli.Get("/");
res->status; // 200
```

### Use a specitic network interface

NOTE: This feature is not available on Windows, yet.

```cpp
cli.set_interface("eth0"); // Interface name, IP address or host name
```

OpenSSL Support
---------------

SSL support is available with `CPPHTTPLIB_OPENSSL_SUPPORT`. `libssl` and `libcrypto` should be linked.

NOTE: cpp-httplib supports 1.1.1 (until 2023-09-11) and 1.0.2 (2019-12-31).

```c++
#define CPPHTTPLIB_OPENSSL_SUPPORT

SSLServer svr("./cert.pem", "./key.pem");

SSLClient cli("localhost", 8080);
cli.set_ca_cert_path("./ca-bundle.crt");
cli.enable_server_certificate_verification(true);
```

Zlib Support
------------

'gzip' compression is available with `CPPHTTPLIB_ZLIB_SUPPORT`.

The server applies gzip compression to the following MIME type contents:

  * all text types
  * image/svg+xml
  * application/javascript
  * application/json
  * application/xml
  * application/xhtml+xml

### Compress content on client

```c++
cli.set_compress(true);
res = cli.Post("/resource/foo", "...", "text/plain");
```

Split httplib.h into .h and .cc
-------------------------------

```bash
> python3 split.py
> ls out
httplib.h  httplib.cc
```

NOTE
----

g++ 4.8 and below cannot build this library since `<regex>` in the versions are [broken](https://stackoverflow.com/questions/12530406/is-gcc-4-8-or-earlier-buggy-about-regular-expressions).

License
-------

MIT license (© 2020 Yuji Hirose)

Special Thanks To
-----------------

The following folks made great contributions to polish this library to totally another level from a simple toy!

  * [Zefz](https://github.com/Zefz)
  * [PixlRainbow](https://github.com/PixlRainbow)
  * [sgraham](https://github.com/sgraham)
  * [mrexodia](https://github.com/mrexodia)
  * [hyperxor](https://github.com/hyperxor)
  * [omaralvarez](https://github.com/omaralvarez)
  * [vvanelslande](https://github.com/vvanelslande)
  * [underscorediscovery](https://github.com/underscorediscovery)
  * [sux2mfgj](https://github.com/sux2mfgj)
  * [matvore](https://github.com/matvore)
  * [intmain-io](https://github.com/intmain)
  * [davidgfnet](https://github.com/davidgfnet)
  * [crtxcr](https://github.com/crtxcr)
  * [const-volatile](https://github.com/const)
  * [aguadoenzo](https://github.com/aguadoenzo)
  * [TheMaverickProgrammer](https://github.com/TheMaverickProgrammer)
  * [vdudouyt](https://github.com/vdudouyt)
  * [stupedama](https://github.com/stupedama)
  * [rockwotj](https://github.com/rockwotj)
  * [marknelson](https://github.com/marknelson)
  * [jaspervandeven](https://github.com/jaspervandeven)
  * [hans-erickson](https://github.com/hans)
  * [ha11owed](https://github.com/ha11owed)
  * [gulrak](https://github.com/gulrak)
  * [dolphineye](https://github.com/dolphineye)
  * [danielzehe](https://github.com/danielzehe)
  * [batist73](https://github.com/batist73)
  * [barryam3](https://github.com/barryam3)
  * [adikabintang](https://github.com/adikabintang)
  * [aaronalbers](https://github.com/aaronalbers)
  * [Whitetigerswt](https://github.com/Whitetigerswt)
  * [TangHuaiZhe](https://github.com/TangHuaiZhe)
  * [Sil3ntStorm](https://github.com/Sil3ntStorm)
  * [MannyClicks](https://github.com/MannyClicks)
  * [DraTeots](https://github.com/DraTeots)
  * [BastienDurel](https://github.com/BastienDurel)
  * [vitalyster](https://github.com/vitalyster)
  * [trollixx](https://github.com/trollixx)
