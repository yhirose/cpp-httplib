#include <cstdint>
#include <cstring>
#include <string>

#include <httplib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  // Use first byte to select which parsing function to exercise
  uint8_t selector = data[0];
  const char *payload = reinterpret_cast<const char *>(data + 1);
  size_t payload_size = size - 1;
  std::string input(payload, payload_size);

  switch (selector % 6) {
  case 0: {
    // parse_query_text
    httplib::Params params;
    httplib::detail::parse_query_text(payload, payload_size, params);
    break;
  }
  case 1: {
    // decode_query_component
    httplib::decode_query_component(input, true);
    httplib::decode_query_component(input, false);
    break;
  }
  case 2: {
    // decode_path_component
    httplib::decode_path_component(input);
    break;
  }
  case 3: {
    // encode_query_component
    httplib::encode_query_component(input);
    break;
  }
  case 4: {
    // normalize_query_string
    httplib::detail::normalize_query_string(input);
    break;
  }
  case 5: {
    // is_valid_path
    httplib::detail::is_valid_path(input);
    break;
  }
  }

  return 0;
}
