#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

#include "fuzzed_stream.h"

// Fixture layout, with <token> unknown to the fuzzer:
//   root/mnt/{index.html,a.txt,data.bin,sub/index.html}  served at /mnt
//   root/mnt/link-in.txt      -> a.txt (stays inside, may be served)
//   root/mnt/link-out.txt     -> ../outside.txt (escapes, must be refused)
//   root/mnt/link-sibling.txt -> ../mnt_secret/secret.txt (shares the "mnt"
//                                prefix, must be refused)
// The response must never contain <token>.

namespace {

FuzzableServer g_server;
std::string g_root;
std::string g_token;
std::vector<std::string> g_paths; // In creation order

void check(bool ok, const char *what) {
  if (!ok) {
    fprintf(stderr, "fixture setup failed: %s\n", what);
    abort();
  }
}

void make_dir(const std::string &path) {
  check(mkdir(path.c_str(), 0755) == 0, path.c_str());
  g_paths.push_back(path);
}

void make_file(const std::string &path, const std::string &content) {
  {
    std::ofstream out(path, std::ios::binary);
    out << content;
    check(out.good(), path.c_str());
  }
  // Fixed, so that conditional requests behave the same in every run
  utimbuf times = {1700000000, 1700000000};
  check(utime(path.c_str(), &times) == 0, path.c_str());
  g_paths.push_back(path);
}

void make_link(const std::string &target, const std::string &path) {
  check(symlink(target.c_str(), path.c_str()) == 0, path.c_str());
  g_paths.push_back(path);
}

std::string serve(const uint8_t *data, size_t size) {
  FuzzedStream stream{data, size};
  g_server.ProcessFuzzedRequest(stream);
  return stream.response();
}

void check_served(const char *path) {
  auto req = std::string("GET ") + path + " HTTP/1.1\r\nHost: x\r\n\r\n";
  auto res = serve(reinterpret_cast<const uint8_t *>(req.data()), req.size());
  // Without this, a fuzzer that serves nothing would pass its check forever
  check(res.find("abcdef") != std::string::npos, path);
}

void remove_fixture() {
  for (auto it = g_paths.rbegin(); it != g_paths.rend(); ++it) {
    if (unlink(it->c_str()) != 0) { rmdir(it->c_str()); }
  }
  rmdir(g_root.c_str());
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  std::random_device rd;
  char token[33];
  snprintf(token, sizeof(token), "%08x%08x%08x%08x", rd(), rd(), rd(), rd());
  g_token = token;

  auto tmpdir = getenv("TMPDIR");
  auto tmpl = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") +
              "/httplib-mount-XXXXXX";
  check(mkdtemp(&tmpl[0]) != nullptr, tmpl.c_str());
  g_root = tmpl;
  atexit(remove_fixture);

  auto mnt = g_root + "/mnt";
  make_dir(mnt);
  make_dir(mnt + "/sub");
  make_dir(g_root + "/mnt_secret");
  make_file(mnt + "/index.html", "<html>index</html>");
  make_file(mnt + "/a.txt", "abcdef");
  make_file(mnt + "/data.bin", std::string("\x01\x02\x03\x04\x05\x06", 6));
  make_file(mnt + "/sub/index.html", "<html>sub</html>");
  make_file(g_root + "/outside.txt", g_token);
  make_file(g_root + "/mnt_secret/secret.txt", g_token);
  make_link("a.txt", mnt + "/link-in.txt");
  make_link("../outside.txt", mnt + "/link-out.txt");
  make_link("../mnt_secret/secret.txt", mnt + "/link-sibling.txt");

  g_server.MarkAsRunning();
  check(g_server.set_mount_point("/mnt", mnt), "set_mount_point");
  check_served("/mnt/a.txt");
  check_served("/mnt/link-in.txt");
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (serve(data, size).find(g_token) != std::string::npos) { abort(); }
  return 0;
}
