#include <cstdint>
#include <cstring>
#include <string>

#include <httplib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  uint8_t selector = data[0];
  const char *payload = reinterpret_cast<const char *>(data + 1);
  size_t payload_size = size - 1;
  std::string input(payload, payload_size);

  switch (selector % 7) {
  case 0: {
    // parse_range_header
    httplib::Ranges ranges;
    httplib::detail::parse_range_header(input, ranges);
    break;
  }
  case 1: {
    // parse_accept_header
    std::vector<std::string> content_types;
    httplib::detail::parse_accept_header(input, content_types);
    break;
  }
  case 2: {
    // extract_media_type with params
    std::map<std::string, std::string> params;
    httplib::detail::extract_media_type(input, &params);
    break;
  }
  case 3: {
    // parse_multipart_boundary
    std::string boundary;
    httplib::detail::parse_multipart_boundary(input, boundary);
    break;
  }
  case 4: {
    // parse_disposition_params
    httplib::Params params;
    httplib::detail::parse_disposition_params(input, params);
    break;
  }
  case 5: {
    // parse_http_date
    httplib::detail::parse_http_date(input);
    break;
  }
  case 6: {
    // can_compress_content_type
    httplib::detail::can_compress_content_type(input);
    break;
  }
  }

  return 0;
}
