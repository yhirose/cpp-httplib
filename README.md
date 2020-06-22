cpp-httplib
===========

[![](https://github.com/yhirose/cpp-httplib/workflows/test/badge.svg)](https://github.com/yhirose/cpp-httplib/actions)
[![Bulid Status](https://ci.appveyor.com/api/projects/status/github/yhirose/cpp-httplib?branch=master&svg=true)](https://ci.appveyor.com/project/yhirose/cpp-httplib)

A C++11 single-file header-only cross platform HTTP/HTTPS library.

It's extremely easy to setup. Just include **httplib.h** file in your code!

For Windows users: Please read [this note](https://github.com/yhirose/cpp-httplib#windows).

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

  svr.Get("/body-header-param", [](const Request& req, Response& res) {
    if (req.has_header("Content-Length")) {
      auto val = req.get_header_value("Content-Length");
    }
    if (req.has_param("key")) {
      auto val = req.get_param_value("key");
    }
    res.set_content(req.body, "text/plain");
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

### Send content with Content provider

```cpp
const size_t DATA_CHUNK_SIZE = 4;

svr.Get("/stream", [&](const Request &req, Response &res) {
  auto data = new std::string("abcdefg");

  res.set_content_provider(
    data->size(), // Content length
    [data](size_t offset, size_t length, DataSink &sink) {
      const auto &d = *data;
      sink.write(&d[offset], std::min(length, DATA_CHUNK_SIZE));
      return true; // return 'false' if you want to cancel the process.
    },
    [data] { delete data; });
});
```

### Chunked transfer encoding

```cpp
svr.Get("/chunked", [&](const Request& req, Response& res) {
  res.set_chunked_content_provider(
    [](size_t offset, DataSink &sink) {
      sink.write("123", 3);
      sink.write("345", 3);
      sink.write("789", 3);
      sink.done();
      return true; // return 'false' if you want to cancel the process.
    }
  );
});
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

### Keep-Alive connection

```cpp
svr.set_keep_alive_max_count(2); // Default is 5
```

### Timeout

```c++
svr.set_read_timeout(5, 0); // 5 seconds
svr.set_write_timeout(5, 0); // 5 seconds
svr.set_idle_interval(0, 100000); // 100 milliseconds
```

### Set maximum payload length for reading request body

```c++
svr.set_payload_max_length(1024 * 1024 * 512); // 512MB
```

### Server-Sent Events

Please check [here](https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc).

### Default thread pool support


`ThreadPool` is used as a default task queue, and the default thread count is set to value from `std::thread::hardware_concurrency()`.

You can change the thread count by setting `CPPHTTPLIB_THREAD_POOL_COUNT`.

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

Client Example
--------------

```c++
#include <httplib.h>
#include <iostream>

int main(void)
{
  // IMPORTANT: 1st parameter must be a hostname or an IP address string.
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
  [&](const char *data, size_t data_length) {
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

### Timeout

```c++
cli.set_connection_timeout(0, 300000); // 300 milliseconds
cli.set_read_timeout(5, 0); // 5 seconds
cli.set_write_timeout(5, 0); // 5 seconds
```

### Receive content with Content receiver

```cpp
std::string body;
auto res = cli.Get(
  "/stream", Headers(),
  [&](const Response &response) {
    EXPECT_EQ(200, response.status);
    return true; // return 'false' if you want to cancel the request.
  },
  [&](const char *data, size_t data_length) {
    body.append(data, data_length);
    return true; // return 'false' if you want to cancel the request.
  });
```

### Send content with Content provider

```cpp
std::string body = ...;
auto res = cli_.Post(
  "/stream", body.size(),
  [](size_t offset, size_t length, DataSink &sink) {
    sink.write(body.data() + offset, length);
    return true; // return 'false' if you want to cancel the request.
  },
  "text/plain");
```

### With Progress Callback

```cpp
httplib::Client client(url, port);

// prints: 0 / 000 bytes => 50% complete
std::shared_ptr<httplib::Response> res =
  cli.Get("/", [](uint64_t len, uint64_t total) {
    printf("%lld / %lld bytes => %d%% complete\n",
      len, total,
      (int)(len*100/total));
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
httplib::Client cli("localhost", 1234);

cli.Get("/hello");         // with "Connection: close"

cli.set_keep_alive(true);
cli.Get("/world");

cli.set_keep_alive(false);
cli.Get("/last-request");  // with "Connection: close"
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

'gzip' compression is available with `CPPHTTPLIB_ZLIB_SUPPORT`. `libz` should be linked.

The server applies gzip compression to the following MIME type contents:

  * all text types
  * image/svg+xml
  * application/javascript
  * application/json
  * application/xml
  * application/xhtml+xml

### Compress request body on client

```c++
cli.set_compress(true);
res = cli.Post("/resource/foo", "...", "text/plain");
```

### Compress response body on client

```c++
cli.set_decompress(false);
res = cli.Get("/resource/foo", {{"Accept-Encoding", "gzip, deflate"}});
res->body; // Compressed data
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

### g++

g++ 4.8 and below cannot build this library since `<regex>` in the versions are [broken](https://stackoverflow.com/questions/12530406/is-gcc-4-8-or-earlier-buggy-about-regular-expressions).

### Windows

Include `httplib.h` before `Windows.h` or include `Windows.h` by defining `WIN32_LEAN_AND_MEAN` beforehand.

```cpp
#include <httplib.h>
#include <Windows.h>
```

```cpp
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <httplib.h>
```

Note: Cygwin on Windows is not supported.

License
-------

MIT license (© 2020 Yuji Hirose)

Special Thanks To
-----------------

[These folks](https://github.com/yhirose/cpp-httplib/graphs/contributors) made great contributions to polish this library to totally another level from a simple toy!
