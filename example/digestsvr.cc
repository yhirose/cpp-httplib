#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
using namespace httplib;

int main(void) {
  Server svr;
  svr.set_digest_auth("user", "pass", "test-digest");

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Authenticated!", "text/plain");
  });

  svr.listen("localhost", 8080);
}