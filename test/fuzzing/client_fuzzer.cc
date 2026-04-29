#include <cstdint>
#include <cstring>
#include <httplib.h>

class FuzzedStream : public httplib::Stream {
public:
  FuzzedStream(const uint8_t *data, size_t size)
      : data_(data), size_(size), read_pos_(0) {}

  ssize_t read(char *ptr, size_t size) override {
    if (size + read_pos_ > size_) { size = size_ - read_pos_; }
    memcpy(ptr, data_ + read_pos_, size);
    read_pos_ += size;
    return static_cast<ssize_t>(size);
  }

  ssize_t write(const char *ptr, size_t size) override {
    request_.append(ptr, size);
    return static_cast<ssize_t>(size);
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
  std::string request_;
};

class FuzzableClient : public httplib::ClientImpl {
public:
  FuzzableClient() : httplib::ClientImpl("localhost", 8080) {}

  void ProcessFuzzedResponse(FuzzedStream &stream, const std::string &method) {
    httplib::Request req;
    req.method = method;
    req.path = "/";
    httplib::Response res;
    bool close_connection = false;
    httplib::Error error = httplib::Error::Success;

    process_request(stream, req, res, close_connection, error);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;

  FuzzedStream stream{data + 1, size - 1};
  FuzzableClient client;

  // Use the first byte to select method
  std::string method;
  switch (data[0] % 6) {
  case 0: method = "GET"; break;
  case 1: method = "POST"; break;
  case 2: method = "PUT"; break;
  case 3: method = "PATCH"; break;
  case 4: method = "DELETE"; break;
  case 5: method = "OPTIONS"; break;
  }

  client.ProcessFuzzedResponse(stream, method);
  return 0;
}
