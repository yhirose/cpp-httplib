#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>

#include <httplib.h>

namespace {

// Feeds the stream in chunks and records every handler call in order
std::string parse_in_chunks(const std::string &stream, size_t chunk,
                            size_t max_event_length) {
  std::string trace;
  httplib::detail::SSEParser parser(
      [&](const httplib::sse::SSEMessage &msg) {
        trace += "event[" + msg.event + "|" + msg.data + "|" + msg.id + "]";
      },
      [&](const std::string &id) { trace += "id[" + id + "]"; },
      [&](int retry_ms) { trace += "retry[" + std::to_string(retry_ms) + "]"; },
      max_event_length);

  for (size_t off = 0; off < stream.size(); off += chunk) {
    if (!parser.parse(stream.data() + off,
                      std::min(chunk, stream.size() - off))) {
      break;
    }
  }
  return trace;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 65536) { return 0; }

  // First byte selects the chunk size, the rest is the event stream
  auto chunk = static_cast<size_t>(data[0]) + 1;
  std::string stream(reinterpret_cast<const char *>(data + 1), size - 1);

  // Without a length limit, chunking must not change what is reported
  auto whole = parse_in_chunks(stream, stream.size(), 0);
  auto chunked = parse_in_chunks(stream, chunk, 0);
  if (whole != chunked) { std::abort(); }

  // With a limit, only check that the parser stops cleanly
  parse_in_chunks(stream, chunk, 64);

  return 0;
}
