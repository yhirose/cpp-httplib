#include <cstdint>
#include <string>

#include <httplib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 65536) return 0;

  // First byte selects the boundary length, the rest is the boundary then body
  size_t boundary_len = (static_cast<size_t>(data[0]) % 16) + 1;
  if (boundary_len + 1 >= size) boundary_len = 0;

  std::string boundary =
      boundary_len > 0
          ? std::string(reinterpret_cast<const char *>(data + 1), boundary_len)
          : "----fuzzboundary";

  const uint8_t *body = data + 1 + boundary_len;
  size_t body_size = size - 1 - boundary_len;

  // FormDataParser::parse, fed in chunks to exercise the streaming paths
  httplib::detail::FormDataParser parser;
  parser.set_boundary(std::move(boundary));

  auto header_cb = [](const httplib::FormData &) -> bool {
    return true;
  };
  auto content_cb = [](const char *, size_t) -> bool {
    return true;
  };

  size_t chunk = (static_cast<size_t>(data[1]) % 64) + 1;
  for (size_t off = 0; off < body_size; off += chunk) {
    size_t n = (off + chunk > body_size) ? body_size - off : chunk;
    if (!parser.parse(reinterpret_cast<const char *>(body + off), n, header_cb,
                      content_cb))
      break;
  }

  return 0;
}
