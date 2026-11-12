#include <cstdint>
#include <cstring>
#include <string>

#include <httplib.h>

// Frame-level fuzzing of the WebSocket wire code. The functions below are the
// exact decoders a hostile peer's bytes reach in production:
// - ws::impl::read_websocket_frame is what WebSocket::read loops on for every
//   incoming frame (server mode expects masked frames, client mode unmasked).
// - detail::read_websocket_upgrade_response parses the handshake response a
//   hostile server sends back to the client's opening request.
// - detail::write_websocket_frame writes payloads an attacker influences (a
//   server echoes Ping/Close payloads back through it).
// - ws::impl::is_valid_utf8 / is_valid_close_payload are the validators the
//   read loop applies verbatim to assembled text-frame and Close payloads.
// Everything else (ports, hosts, the request path) is trusted application
// configuration and is held fixed, per the threat model.

namespace {

// A stream whose reads consume fuzz bytes and whose writes are recorded.
class FuzzedWsStream : public httplib::Stream {
public:
  FuzzedWsStream(const uint8_t *data, size_t size)
      : data_(data), size_(size), read_pos_(0) {}

  ssize_t read(char *ptr, size_t size) override {
    if (read_pos_ >= size_) { return 0; }
    if (size + read_pos_ > size_) { size = size_ - read_pos_; }
    memcpy(ptr, data_ + read_pos_, size);
    read_pos_ += size;
    return static_cast<ssize_t>(size);
  }

  ssize_t write(const char *ptr, size_t size) override {
    response_.append(ptr, size);
    return static_cast<ssize_t>(size);
  }

  bool is_readable() const override { return read_pos_ < size_; }

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
  std::string response_;
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) { return 0; }

  uint8_t selector = data[0];
  const char *payload = reinterpret_cast<const char *>(data + 1);
  size_t payload_size = size - 1;
  std::string bytes(payload, payload_size);

  switch (selector % 7) {
  case 0: {
    // Server side: client frames arrive masked. Vary max_len over the
    // documented caller choices (0 = unlimited, per payload_max_length).
    static const size_t max_lens[] = {0, 125, 4096, 1u << 20};
    size_t max_len = max_lens[(selector / 7) % 4];
    httplib::ws::Opcode opcode = httplib::ws::Opcode::Text;
    std::string frame_payload;
    bool fin = false;
    FuzzedWsStream strm(data + 1, size - 1);
    httplib::ws::impl::read_websocket_frame(strm, opcode, frame_payload, fin,
                                            /*expect_masked=*/true, max_len);
    break;
  }
  case 1: {
    // Client side: server frames arrive unmasked.
    static const size_t max_lens[] = {0, 125, 4096, 1u << 20};
    size_t max_len = max_lens[(selector / 7) % 4];
    httplib::ws::Opcode opcode = httplib::ws::Opcode::Text;
    std::string frame_payload;
    bool fin = false;
    FuzzedWsStream strm(data + 1, size - 1);
    httplib::ws::impl::read_websocket_frame(strm, opcode, frame_payload, fin,
                                            /*expect_masked=*/false, max_len);
    break;
  }
  case 2: {
    // Frame writer: echoes attacker-influenced payload (Ping/Close replies).
    FuzzedWsStream strm(data + 1, size - 1);
    auto opcode = static_cast<httplib::ws::Opcode>((selector / 14) & 0x0F);
    bool mask = ((selector / 7) % 2) != 0;
    httplib::detail::write_websocket_frame(strm, opcode, bytes.data(),
                                           bytes.size(), /*fin=*/true, mask);
    break;
  }
  case 3: {
    // Text-frame payload validator, as applied by WebSocket::read.
    httplib::ws::impl::is_valid_utf8(bytes);
    break;
  }
  case 4: {
    // Close-frame payload validator.
    httplib::ws::impl::is_valid_close_payload(bytes);
    break;
  }
  case 5: {
    // Handshake response reading: the hostile server controls every byte.
    FuzzedWsStream strm(data + 1, size - 1);
    // The expected accept is computed from the client key exactly as
    // perform_websocket_handshake does; the key is trusted configuration.
    const std::string client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    std::string expected_accept =
        httplib::detail::websocket_accept_key(client_key);
    httplib::detail::WebSocketUpgradeResponse upgrade;
    httplib::detail::read_websocket_upgrade_response(
        strm, expected_accept, /*offered_subprotocols=*/"chat, stream",
        upgrade);
    break;
  }
  case 6: {
    // Full client handshake: fixed application request, hostile response.
    FuzzedWsStream strm(data + 1, size - 1);
    httplib::Request req;
    req.method = "GET";
    req.path = "/";
    req.headers.emplace("Host", "example.com");
    httplib::detail::WebSocketUpgradeResponse upgrade;
    httplib::detail::perform_websocket_handshake(strm, req, upgrade);
    break;
  }
  }

  return 0;
}
