#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <httplib.h>

// Client flow fuzzing over a fabricated connection. The fuzz input selects a
// client configuration matrix (proxy + no-proxy patterns, basic auth, digest
// auth, compressed uploads, chunked uploads, multipart uploads, response
// decompression) and the response bytes the peer sends; a subclassed
// create_and_connect_socket() hands the client one end of an AF_UNIX
// socketpair, so no real network is ever touched. The request bytes the
// client writes (request-line serialization, proxy absolute-form, credential
// headers, provider bodies) are consumed by the peer thread; redirect
// following is deliberately NOT enabled: a cross-host redirect constructs a
// fresh real client that would escape this seam and dial the network.

namespace {

// Plays the remote peer: reads request bytes until a request head ends,
// answers with the scripted responses, then drains until EOF.
class FakePeer {
public:
  FakePeer(int fd, const std::string &r1, const std::string &r2)
      : fd_(fd), r1_(r1), r2_(r2), thread_(&FakePeer::run, this) {}

  ~FakePeer() {
    if (fd_ >= 0) {
      ::shutdown(fd_, SHUT_RDWR);
      ::close(fd_);
      fd_ = -1;
    }
    if (thread_.joinable()) { thread_.join(); }
  }

  FakePeer(const FakePeer &) = delete;
  FakePeer &operator=(const FakePeer &) = delete;

private:
  static bool wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    return ::poll(&pfd, 1, timeout_ms) == 1 && (pfd.revents & POLLIN);
  }

  void run() {
    std::string buf;
    int served = 0;
    while (true) {
      if (!wait_readable(fd_, 3000)) { break; }
      char chunk[4096];
      ssize_t n = ::read(fd_, chunk, sizeof(chunk));
      if (n <= 0) { break; }
      buf.append(chunk, static_cast<size_t>(n));
      // Serve one response per completed request head.
      while (buf.find("\r\n\r\n") != std::string::npos) {
        buf.clear();
        const std::string &resp = (served == 0) ? r1_ : r2_;
        size_t off = 0;
        while (off < resp.size()) {
          ssize_t w = ::write(fd_, resp.data() + off, resp.size() - off);
          if (w <= 0) { return; }
          off += static_cast<size_t>(w);
        }
        served++;
        if (served >= 2) {
          // Second round done: half-close so the client sees EOF.
          ::shutdown(fd_, SHUT_WR);
        }
        break;
      }
      if (served >= 2 && buf.size() > 1u << 20) { break; }
    }
  }

  int fd_;
  std::string r1_;
  std::string r2_;
  std::thread thread_;
};

// Hands the client the client-side end of a socketpair instead of a socket,
// and spawns a peer thread scripted with the fuzzed responses.
class FuzzableClient : public httplib::ClientImpl {
public:
  FuzzableClient() : httplib::ClientImpl("unit.test", 18080) {}

  bool create_and_connect_socket(Socket &socket,
                                 httplib::Error &error) override {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
      error = httplib::Error::Connection;
      return false;
    }
    socket.sock = fds[1];
    peer_.reset(new FakePeer(fds[0], r1_, r2_));
    return true;
  }

  void script_peer(const std::string &r1, const std::string &r2) {
    r1_ = r1;
    r2_ = r2;
  }

private:
  std::string r1_;
  std::string r2_;
  std::unique_ptr<FakePeer> peer_;
};

// Input layout: [selector][resp1 len u16 LE][resp1][resp2 len u16 LE][resp2]
// [case-specific params]. The two response scripts are what a hostile server
// would send (the second is used by the digest-auth 401 retry round).
bool parse_frame(const uint8_t *data, size_t size, uint8_t &selector,
                 std::string &r1, std::string &r2, const uint8_t *&params,
                 size_t &params_size) {
  if (size < 5) { return false; }
  size_t off = 0;
  selector = data[off++];
  uint16_t n1 = static_cast<uint16_t>(data[off] | (data[off + 1] << 8));
  off += 2;
  if (off + n1 + 2 > size) { return false; }
  r1.assign(reinterpret_cast<const char *>(data) + off, n1);
  off += n1;
  uint16_t n2 = static_cast<uint16_t>(data[off] | (data[off + 1] << 8));
  off += 2;
  if (off + n2 > size) { return false; }
  r2.assign(reinterpret_cast<const char *>(data) + off, n2);
  off += n2;
  params = data + off;
  params_size = size - off;
  return true;
}

// Splits params into '\n'-separated lines (used as config strings).
std::vector<std::string> split_lines(const uint8_t *p, size_t n) {
  std::vector<std::string> out;
  std::string all(reinterpret_cast<const char *>(p), n);
  size_t start = 0;
  while (true) {
    size_t nl = all.find('\n', start);
    if (nl == std::string::npos) {
      out.push_back(all.substr(start));
      break;
    }
    out.push_back(all.substr(start, nl - start));
    start = nl + 1;
  }
  return out;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t selector = 0;
  std::string r1, r2;
  const uint8_t *params = nullptr;
  size_t params_size = 0;
  if (!parse_frame(data, size, selector, r1, r2, params, params_size)) {
    return 0;
  }

  FuzzableClient client;
  // Trusted configuration: tight timeouts so a peer that stops talking ends
  // the request quickly; never any DNS or network egress (fabricated socket).
  client.set_connection_timeout(1, 0);
  client.set_read_timeout(1, 0);
  client.set_write_timeout(1, 0);
  client.script_peer(r1, r2);

  switch (selector % 8) {
  case 0: {
    // Proxy + no-proxy matrix: set_no_proxy parsing/matching, proxy
    // absolute-form request-line building.
    std::vector<std::string> patterns = split_lines(params, params_size);
    client.set_proxy("proxy.unit.test", 18081);
    client.set_no_proxy(patterns);
    auto res = client.Get("/");
    (void)res;
    break;
  }
  case 1: {
    // Credential headers: basic auth (and bearer token on one selector bit).
    std::vector<std::string> f = split_lines(params, params_size);
    if (f.size() >= 3) {
      client.set_basic_auth(f[0], f[1]);
      if ((selector / 8) % 2 == 0) { client.set_bearer_token_auth(f[2]); }
      httplib::Headers headers;
      headers.emplace("X-Fuzz", f[2]);
      auto res = client.Get("/", headers);
      (void)res;
    }
    break;
  }
#if defined(CPPHTTPLIB_OPENSSL_SUPPORT)
  case 2: {
    // Digest auth: the peer answers with a hostile 401 challenge, the client
    // parses it and retries with computed credentials.
    std::vector<std::string> f = split_lines(params, params_size);
    if (f.size() >= 2) {
      client.set_digest_auth(f[0], f[1]);
      auto res = client.Get("/");
      (void)res;
    }
    break;
  }
#endif
  case 3: {
    // Multipart upload: item serialization, boundary generation,
    // content-length computation, upload progress.
    std::vector<std::string> f = split_lines(params, params_size);
    if (f.size() >= 4) {
      httplib::UploadFormDataItems items;
      httplib::UploadFormData a;
      a.name = "field";
      a.content = f[0];
      a.filename = f[1];
      a.content_type = f[2];
      items.push_back(a);
      httplib::UploadFormData b;
      b.name = "file";
      b.content = f[3];
      b.filename = f[0];
      b.content_type = "application/octet-stream";
      items.push_back(b);
      auto res =
          client.Post("/upload", items, [](size_t, size_t) { return true; });
      (void)res;
    }
    break;
  }
  case 4: {
    // Chunked upload through a length-less content provider.
    std::vector<std::string> f = split_lines(params, params_size);
    std::string content_type = f.empty() ? std::string("text/plain") : f[0];
    std::string bytes(reinterpret_cast<const char *>(params), params_size);
    auto res = client.Post(
        "/chunked",
        [&bytes](size_t offset, httplib::DataSink &sink) -> bool {
          if (offset >= bytes.size()) {
            sink.done();
            return true;
          }
          size_t n = bytes.size() - offset;
          if (n > 64) { n = 64; }
          sink.write(bytes.data() + offset, n);
          return true;
        },
        content_type, [](size_t, size_t) { return true; });
    (void)res;
    break;
  }
  case 5: {
    // Compressed request body (request-side compressor path).
    std::vector<std::string> f = split_lines(params, params_size);
    std::string content_type = f.empty() ? std::string("text/plain") : f[0];
    std::string body = f.empty() ? std::string() : f.back();
    client.set_compress(true);
    auto res = client.Post("/compressed", body, content_type,
                           [](size_t, size_t) { return true; });
    (void)res;
    break;
  }
  case 6: {
    // Response decompression: the peer's Content-Encoding drives the
    // client's decompressor choice over the receiver path.
    auto res = client.Get("/", httplib::Headers(),
                          [](const char *data, size_t len) -> bool {
                            (void)data;
                            (void)len;
                            return true;
                          },
                          [](size_t, size_t) { return true; });
    (void)res;
    break;
  }
  case 7: {
    // Method/status matrix with fuzz headers through the response handler.
    std::vector<std::string> f = split_lines(params, params_size);
    httplib::Headers headers;
    if (!f.empty() && !f[0].empty()) {
      headers.emplace("X-Fuzz-Key", f[0]);
    }
    std::string body = f.size() > 1 ? f[1] : std::string();
    auto handler = [](const httplib::Response &response) -> bool {
      (void)response;
      return true;
    };
    auto receiver = [](const char *data, size_t len) -> bool {
      (void)data;
      (void)len;
      return true;
    };
    switch ((selector / 8) % 6) {
    case 0: client.Get("/m", headers, handler, receiver); break;
    case 1:
      client.Post("/m", body, "text/plain", httplib::UploadProgress());
      break;
    case 2:
      client.Put("/m", body, "text/plain", httplib::UploadProgress());
      break;
    case 3:
      client.Patch("/m", body, "text/plain", httplib::UploadProgress());
      break;
    case 4: client.Delete("/m", headers); break;
    case 5: client.Head("/m", headers); break;
    }
    break;
  }
  }

  return 0;
}
