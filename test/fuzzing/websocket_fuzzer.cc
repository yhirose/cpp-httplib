#include <cstdint>
#include <string>

#include <httplib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) { return 0; }

  auto selector = data[0];
  std::string input(reinterpret_cast<const char *>(data + 1), size - 1);

  switch (selector % 4) {
  case 0: {
    // read_websocket_frame. WebSocket::read passes the macro, close() passes
    // 125, and 0 means no limit
    static const size_t max_lens[] = {0, 125,
                                      CPPHTTPLIB_WEBSOCKET_MAX_PAYLOAD_LENGTH};
    auto expect_masked = (selector / 4) % 2 != 0;
    auto max_len = max_lens[(selector / 8) % 3];
    httplib::detail::BufferStream strm;
    strm.write(input.data(), input.size());
    auto opcode = httplib::ws::Opcode::Text;
    std::string payload;
    auto fin = false;
    httplib::ws::impl::read_websocket_frame(strm, opcode, payload, fin,
                                            expect_masked, max_len);
    break;
  }
  case 1: {
    // is_valid_utf8
    httplib::ws::impl::is_valid_utf8(input);
    break;
  }
  case 2: {
    // is_valid_close_payload
    httplib::ws::impl::is_valid_close_payload(input);
    break;
  }
  case 3: {
    // read_websocket_upgrade_response, with a fixed key since
    // perform_websocket_handshake draws a random one
    static const auto expected_accept =
        httplib::detail::websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    httplib::detail::BufferStream strm;
    strm.write(input.data(), input.size());
    httplib::detail::WebSocketUpgradeResponse upgrade;
    httplib::detail::read_websocket_upgrade_response(strm, expected_accept,
                                                     "chat, stream", upgrade);
    break;
  }
  }

  return 0;
}
