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

      sink.done();

      return true;
    };
  }

  httplib::ResponseHandler response_handler;
  response_handler = [&](const httplib::Response &response) {
    printf("ResponseHandler ==> Status: %d\n", response.status);
    return true; // return 'false' if you want to cancel the request.
  };

  httplib::ContentReceiver content_receiver;
  std::ofstream sample_output_file("./ca-bundle-downloaded.crt", std::ios::out | std::ios::binary);
  if (sample_output_file) {
    content_receiver = [&](const char *data, size_t data_length) {
      sample_output_file.write(data, data_length);
      return true;
    };
  }

  httplib::Progress progress_tracker;
  progress_tracker = [](uint64_t len, uint64_t total) {
    printf("Progress ===> %lld / %lld bytes (%d%% complete)\n", len, total, (int)(len * 100 / total));
    return true; // return 'false' if you want to cancel the request.
  };

  // It can be a post and patch request.
  if (auto res = cli.Put(
          "/upload_receiver", headers, params, stream_size, content_provider,
          "application/octet-stream", response_handler, content_receiver,
          progress_tracker)) {
      std::cout << "Cert uploaded and downloaded." << std::endl;
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
