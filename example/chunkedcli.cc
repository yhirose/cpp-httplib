//
//  chunkedcli.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>
#include <iostream>

#define CA_CERT_FILE "./ca-bundle.crt"

int main(void) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli("localhost");
  // httplib::SSLClient cli("google.com");
  // httplib::SSLClient cli("www.youtube.com");
  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.enable_server_certificate_verification(true);
#else
  httplib::Client cli("localhost", 8080);
#endif

  httplib::Headers headers;
  httplib::Params params;
  size_t stream_size = 0;

  httplib::ContentProvider content_provider;
  std::ifstream sample_input_file("./ca-bundle.crt", std::ios::in | std::ios::binary);

  if (sample_input_file) {
    content_provider = [&](size_t offset, size_t length, httplib::DataSink &sink) {
      do {
        char buffer[CPPHTTPLIB_RECV_BUFSIZ];
        sample_input_file.read(buffer, CPPHTTPLIB_RECV_BUFSIZ);
        unsigned int readBytes = sample_input_file.gcount();
        if (readBytes > 0) {
          sink.write(buffer + offset, readBytes);
          printf("ContentProvider ==> Written Bytes: %lld\n", sample_input_file.gcount());
        }
      } while (sample_input_file.gcount() > 0);

      return true;
    };
  }

  // It can be a post and patch request.
  if (auto res = cli.Put(
          "/upload_receiver", headers, stream_size, content_provider,
          "application/octet-stream")) {
      std::cout << "Cert uploaded." << std::endl;
  } else {
      std::cout << "error code: " << res.error() << std::endl;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto result = cli.get_openssl_verify_result();
    if (result) {
        std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
    }
#endif
  }

  return 0;
}
