#include "fuzzed_stream.h"

static FuzzableServer g_server;

extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  g_server.Get(R"(.*)",
               [&](const httplib::Request & /*req*/, httplib::Response &res) {
                 res.set_content("response content", "text/plain");
               });
  g_server.Post(R"(.*)",
                [&](const httplib::Request & /*req*/, httplib::Response &res) {
                  res.set_content("response content", "text/plain");
                });
  g_server.Put(R"(.*)",
               [&](const httplib::Request & /*req*/, httplib::Response &res) {
                 res.set_content("response content", "text/plain");
               });
  g_server.Patch(R"(.*)",
                 [&](const httplib::Request & /*req*/, httplib::Response &res) {
                   res.set_content("response content", "text/plain");
                 });
  g_server.Delete(
      R"(.*)", [&](const httplib::Request & /*req*/, httplib::Response &res) {
        res.set_content("response content", "text/plain");
      });
  g_server.Options(
      R"(.*)", [&](const httplib::Request & /*req*/, httplib::Response &res) {
        res.set_content("response content", "text/plain");
      });
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedStream stream{data, size};
  g_server.ProcessFuzzedRequest(stream);
  return 0;
}
