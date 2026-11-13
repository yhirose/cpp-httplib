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

  switch (selector % 13) {
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
  case 6: {
    // parse_url
    httplib::detail::UrlComponents uc;
    httplib::detail::parse_url(input, uc);
    break;
  }
  case 7: {
    // remove_dot_segments
    httplib::detail::remove_dot_segments(input);
    break;
  }
  case 8: {
    // resolve_relative_location, with the input as "<location>\n<base>"
    auto nl = input.find('\n');
    auto location = input.substr(0, nl);
    auto base = nl == std::string::npos ? std::string("/index.html")
                                        : input.substr(nl + 1);
    httplib::detail::resolve_relative_location(location, base);
    break;
  }
  case 9: {
    // encode_path
    httplib::detail::encode_path(input);
    break;
  }
  case 10: {
    // encode_uri_component, encode_uri
    httplib::encode_uri_component(input);
    httplib::encode_uri(input);
    break;
  }
  case 11: {
    // decode_uri_component, decode_uri
    httplib::decode_uri_component(input);
    httplib::decode_uri(input);
    break;
  }
  case 12: {
    // sanitize_filename
    httplib::sanitize_filename(input);
    break;
  }
  }

  return 0;
}
