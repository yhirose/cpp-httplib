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
    // parse_url: full URL parsing (scheme, host, port, path, query); the
    // request-target and Location values an attacker supplies are its input.
    httplib::detail::UrlComponents uc;
    httplib::detail::parse_url(input, uc);
    break;
  }
  case 7: {
    // remove_dot_segments: RFC 3986 path normalization used on request and
    // redirect paths (traversal surface).
    httplib::detail::remove_dot_segments(input);
    break;
  }
  case 8: {
    // resolve_relative_location: resolves a hostile Location value against
    // the current request path during redirects. Split the fuzz input at the
    // first '\n' into location and base; default base when absent.
    std::string location = input;
    std::string base = "/index.html";
    auto nl = input.find('\n');
    if (nl != std::string::npos) {
      location = input.substr(0, nl);
      base = input.substr(nl + 1);
    }
    httplib::detail::resolve_relative_location(location, base);
    break;
  }
  case 9: {
    // encode_path: percent-encoding applied to request/redirect path parts.
    httplib::detail::encode_path(input);
    break;
  }
  case 10: {
    // Public URI encoders (also applied to attacker-derived strings, e.g.
    // when a client echoes back path or query parts).
    httplib::encode_uri_component(input);
    httplib::encode_uri(input);
    break;
  }
  case 11: {
    // Public URI decoders.
    httplib::decode_uri_component(input);
    httplib::decode_uri(input);
    break;
  }
  case 12: {
    // Filename sanitizer (public utility applied to user-supplied filenames,
    // e.g. when composing Content-Disposition values).
    httplib::sanitize_filename(input);
    break;
  }
  }

  return 0;
}
