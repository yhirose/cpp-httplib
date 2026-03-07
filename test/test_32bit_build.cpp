#include "../httplib.h"

int main() {
  httplib::Server svr;
  httplib::Client cli("localhost", 8080);
  (void)svr;
  (void)cli;
  return 0;
}
