#include "httplib.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

using namespace httplib;

namespace {

// The workloads differ in which part of the write path they exercise:
//
//   /                 small body set through set_content(); the response line,
//                     the headers and the body already share a single write()
//   /large            large body set through set_content(); the body is copied
//                     into the header buffer before that single write().
//                     --large-mib sets its size (and large.bin's).
//   /static/small.js  small file served from a mount point, where the headers
//                     and the body are two separate writes
//   /static/large.bin same, with the body large enough to dominate
//
// Bodies are generated at startup so the repository carries no fixtures.

const size_t SMALL_SIZE = 1024;
const size_t LARGE_SIZE_DEFAULT_MIB = 1;

std::string filler(size_t n) {
  std::string s;
  s.reserve(n);
  while (s.size() < n) {
    s += "0123456789abcdef";
  }
  s.resize(n);
  return s;
}

bool write_file(const std::string &path, const std::string &content) {
  std::ofstream f(path.c_str(), std::ios::binary);
  f.write(content.data(), static_cast<std::streamsize>(content.size()));
  return f.good();
}

std::string default_dir() {
  const char *tmp = std::getenv("TMPDIR");
  std::string base = tmp && *tmp ? tmp : "/tmp";
  if (!base.empty() && base[base.size() - 1] == '/') {
    base.erase(base.size() - 1);
  }
  return base + "/cpp-httplib-bench";
}

bool make_dir(const std::string &path) {
#ifdef _WIN32
  return _mkdir(path.c_str()) == 0 || errno == EEXIST;
#else
  return ::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

void setup(Server &svr, const std::string &large, const std::string &dir) {
  svr.Get("/", [](const Request &, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  svr.Get("/large", [&large](const Request &, Response &res) {
    res.set_content(large, "application/octet-stream");
  });

  svr.set_mount_point("/static", dir);
}

} // namespace

int main(int argc, char *argv[]) {
  int port = 8080;
  std::string dir = default_dir();
  std::string cert;
  std::string key;
  size_t large_mib = LARGE_SIZE_DEFAULT_MIB;

  for (int i = 1; i < argc; i++) {
    auto last = i + 1 < argc;
    if (!std::strcmp(argv[i], "--port") && last) {
      port = std::atoi(argv[++i]);
    } else if (!std::strcmp(argv[i], "--large-mib") && last) {
      large_mib = static_cast<size_t>(std::atoi(argv[++i]));
    } else if (!std::strcmp(argv[i], "--dir") && last) {
      dir = argv[++i];
    } else if (!std::strcmp(argv[i], "--cert") && last) {
      cert = argv[++i];
    } else if (!std::strcmp(argv[i], "--key") && last) {
      key = argv[++i];
    } else {
      std::fprintf(stderr,
                   "usage: %s [--port N] [--dir PATH] [--large-mib N]"
                   " [--cert PATH --key PATH]\n",
                   argv[0]);
      return 2;
    }
  }

  if (!make_dir(dir)) {
    std::fprintf(stderr, "cannot create %s\n", dir.c_str());
    return 1;
  }

  auto large = filler(large_mib * 1024 * 1024);
  if (!write_file(dir + "/small.js", filler(SMALL_SIZE)) ||
      !write_file(dir + "/large.bin", large)) {
    std::fprintf(stderr, "cannot write fixtures under %s\n", dir.c_str());
    return 1;
  }

  if (!cert.empty()) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLServer svr(cert.c_str(), key.c_str());
    if (!svr.is_valid()) {
      std::fprintf(stderr, "cannot load %s / %s\n", cert.c_str(), key.c_str());
      return 1;
    }
    setup(svr, large, dir);
    svr.listen("0.0.0.0", port);
    return 0;
#else
    std::fprintf(stderr, "built without CPPHTTPLIB_OPENSSL_SUPPORT\n");
    return 1;
#endif
  }

  Server svr;
  setup(svr, large, dir);
  svr.listen("0.0.0.0", port);
}
