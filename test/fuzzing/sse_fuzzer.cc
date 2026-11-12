#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <httplib.h>

// SSE client streaming over a loopback listener. SSEClient::run_event_loop()
// is private and driven by start(); it requires a full HTTP 200 streaming
// response (Client::open_stream) before any SSE line is parsed, so the fuzz
// input is the raw bytes a hostile event-stream server sends: status line,
// headers, body. Everything stays on 127.0.0.1 with an ephemeral port; the
// listener serves the scripted bytes once and closes, so reconnects hit EOF
// and end the loop.

namespace {

class LoopbackServer {
public:
  LoopbackServer(const std::string &resp) : resp_(resp) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) { return; }
    int reuse = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd_, reinterpret_cast<struct sockaddr *>(&addr),
               sizeof(addr)) != 0 ||
        ::listen(fd_, 4) != 0) {
      ::close(fd_);
      fd_ = -1;
      return;
    }
    struct sockaddr_in bound;
    socklen_t len = sizeof(bound);
    ::getsockname(fd_, reinterpret_cast<struct sockaddr *>(&bound), &len);
    port_ = ::ntohs(bound.sin_port);
    thread_ = std::thread(&LoopbackServer::run, this);
  }

  ~LoopbackServer() {
    if (fd_ >= 0) { ::close(fd_); }
    if (thread_.joinable()) { thread_.join(); }
  }

  int port() const { return port_; }

private:
  static bool wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    return ::poll(&pfd, 1, timeout_ms) == 1 && (pfd.revents & POLLIN);
  }

  void serve_one(int cfd) {
    // The client's request never depends on the fuzz input, so answer
    // immediately on accept and force-close quickly: a hostile peer that
    // answers and hangs up. This keeps the per-input wall time tiny.
    size_t off = 0;
    while (off < resp_.size()) {
      ssize_t w = ::write(cfd, resp_.data() + off, resp_.size() - off);
      if (w <= 0) { break; }
      off += static_cast<size_t>(w);
    }
    ::shutdown(cfd, SHUT_WR);
    // Brief drain so the client's inbound bytes never fill the send buffer,
    // then force-close.
    char buf[4096];
    for (int i = 0; i < 2; i++) {
      if (!wait_readable(cfd, 200)) { break; }
      if (::read(cfd, buf, sizeof(buf)) <= 0) { break; }
    }
    ::close(cfd);
  }

  void run() {
    for (int i = 0; i < 2; i++) {
      if (!wait_readable(fd_, 500)) { break; }
      int cfd = ::accept(fd_, nullptr, nullptr);
      if (cfd < 0) { break; }
      serve_one(cfd);
    }
  }

  int fd_ = -1;
  int port_ = 0;
  std::string resp_;
  std::thread thread_;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) { return 0; }
  std::string response(reinterpret_cast<const char *>(data), size);

  LoopbackServer server(response);
  if (server.port() == 0) { return 0; }

  httplib::Client client("127.0.0.1", server.port());
  httplib::sse::SSEClient sse(client, "/events");
  sse.set_reconnect_interval(1);
  sse.set_max_reconnect_attempts(1);
  sse.on_message([](const httplib::sse::SSEMessage &) {});
  sse.on_event("fuzz", [](const httplib::sse::SSEMessage &) {});
  sse.on_error([](httplib::Error) {});
  client.set_connection_timeout(1, 0);
  client.set_read_timeout(1, 0);
  sse.start();
  return 0;
}
