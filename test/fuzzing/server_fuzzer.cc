#include <cstdint>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

#include <httplib.h>

// Static-file serving fixture. Handler patterns exclude /mnt/ so those
// requests fall through to the mount point, exercising handle_file_request:
// path traversal defenses (is_valid_path, canonicalize_path,
// is_path_within_base), ETag/conditional requests, range serving and mmap
// read-back of attacker-named files.
static const char *kMountDir = "/tmp/cpp-httplib-fuzz-mount";

static void write_fixture(const std::string &path, const std::string &content) {
  std::ofstream out(path.c_str(), std::ios::binary);
  out << content;
}

class FuzzedStream : public httplib::Stream {
public:
  FuzzedStream(const uint8_t *data, size_t size)
      : data_(data), size_(size), read_pos_(0) {}

  ssize_t read(char *ptr, size_t size) override {
    if (size + read_pos_ > size_) { size = size_ - read_pos_; }
    memcpy(ptr, data_ + read_pos_, size);
    read_pos_ += size;
    // Like SocketStream, pull in more than was asked for, which the line
    // reader then takes through buffered_data(), so both of its paths run.
    buffered_end_ =
        (std::max)(buffered_end_, (std::min)(size_, read_pos_ + 4096));
    return static_cast<ssize_t>(size);
  }

  const char *buffered_data(size_t &size) const override {
    size = buffered_end_ > read_pos_ ? buffered_end_ - read_pos_ : 0;
    return size ? reinterpret_cast<const char *>(data_ + read_pos_) : nullptr;
  }

  void consume_buffered(size_t size) override { read_pos_ += size; }

  ssize_t write(const char *ptr, size_t size) override {
    response_.append(ptr, size);
    return static_cast<int>(size);
  }

  ssize_t write(const char *ptr) { return write(ptr, strlen(ptr)); }

  ssize_t write(const std::string &s) { return write(s.data(), s.size()); }

  bool is_readable() const override { return true; }

  bool wait_readable() const override { return true; }

  bool wait_writable() const override { return true; }

  void get_remote_ip_and_port(std::string &ip, int &port) const override {
    ip = "127.0.0.1";
    port = 8080;
  }

  void get_local_ip_and_port(std::string &ip, int &port) const override {
    ip = "127.0.0.1";
    port = 8080;
  }

  socket_t socket() const override { return 0; }

  time_t duration() const override { return 0; };

private:
  const uint8_t *data_;
  size_t size_;
  size_t read_pos_;
  size_t buffered_end_ = 0;
  std::string response_;
};

class FuzzableServer : public httplib::Server {
public:
  void ProcessFuzzedRequest(FuzzedStream &stream) {
    bool connection_close = false;
    process_request(stream,
                    /*remote_addr=*/"",
                    /*remote_port =*/0,
                    /*local_addr=*/"",
                    /*local_port =*/0,
                    /*last_connection=*/false, connection_close, nullptr);
  }
};

static FuzzableServer g_server;

extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  ::mkdir(kMountDir, 0755);
  std::string sub = std::string(kMountDir) + "/sub";
  ::mkdir(sub.c_str(), 0755);
  write_fixture(std::string(kMountDir) + "/index.html",
                "<html>fixture index</html>");
  write_fixture(std::string(kMountDir) + "/a.txt", "abcdef");
  write_fixture(std::string(kMountDir) + "/data.bin",
                std::string("\x01\x02\x03\x04\x05\x06\x07\x08", 8));
  write_fixture(sub + "/index.html", "<html>sub index</html>");
  // A symlink that escapes the mount (must be refused) and one that stays
  // inside it (may be served).
  ::symlink("/etc/passwd", (std::string(kMountDir) + "/link-out.txt").c_str());
  ::symlink("./a.txt", (std::string(kMountDir) + "/link-in.txt").c_str());

  g_server.set_mount_point("/mnt", kMountDir);
  g_server.set_file_request_handler(
      [](const httplib::Request &, httplib::Response &) {});

  g_server.Get(R"(^(?!/mnt/).*)",
               [&](const httplib::Request & /*req*/, httplib::Response &res) {
                 res.set_content("response content", "text/plain");
               });
  g_server.Post(R"(^(?!/mnt/).*)",
                [&](const httplib::Request & /*req*/, httplib::Response &res) {
                  res.set_content("response content", "text/plain");
                });
  g_server.Put(R"(^(?!/mnt/).*)",
               [&](const httplib::Request & /*req*/, httplib::Response &res) {
                 res.set_content("response content", "text/plain");
               });
  g_server.Patch(R"(^(?!/mnt/).*)",
                 [&](const httplib::Request & /*req*/, httplib::Response &res) {
                   res.set_content("response content", "text/plain");
                 });
  g_server.Delete(
      R"(^(?!/mnt/).*)", [&](const httplib::Request & /*req*/,
                             httplib::Response &res) {
        res.set_content("response content", "text/plain");
      });
  g_server.Options(
      R"(^(?!/mnt/).*)", [&](const httplib::Request & /*req*/,
                             httplib::Response &res) {
        res.set_content("response content", "text/plain");
      });
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedStream stream{data, size};
  g_server.ProcessFuzzedRequest(stream);
  return 0;
}
