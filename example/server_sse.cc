#include <filesystem>
#include <getopt.h>
#include <httplib.h>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <unistd.h>

#define HTTP_SERVER_PORT 1234

using namespace std;

map<socket_t, httplib::detail::SseEmitter> sseEmitterMap;

int main(int argc, char *argv[]) {

  httplib::Server svr;
  svr.set_default_headers({
      {"Access-Control-Allow-Origin", "*"},
      {"Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS,PATCH, DELETE"},
      {"Access-Control-Max-Age", "3600"},
      {"Access-Control-Allow-Headers", "*"},
  });

  svr.Options(R"(/.+)", [](const auto &req, auto &res) {
    res.set_header("Allow", "GET, POST, HEAD,PATCH, OPTIONS");
  });

  svr.Get("/sse", [](const httplib::Request &req, httplib::Response &res) {
    string data = "event: log\nid: 0\ndata: sse test\nretry: 3000\n\n\n";
    res.set_content(data, "text/event-stream; charset=UTF-8");
    httplib::detail::SseEmitter sseEmitter(req.sock_fd);
    sseEmitterMap[req.sock_fd] = sseEmitter;
  });
  thread t([] {
    int id = 1;
    while (true) {
      this_thread::sleep_for(chrono::seconds(1));
      if (sseEmitterMap.size() < 1) { continue; }
      cout << "send event: " << id << std::endl;
      vector<socket_t> clearSocktFds;
      for (auto sseEmitter : sseEmitterMap) {
        sseEmitter.second.id = id;
        sseEmitter.second.event = "message";
        sseEmitter.second.data = "test ==> " + to_string(id);
        if (sseEmitter.second.send() == -1) {
          clearSocktFds.push_back(sseEmitter.first);
        }
      }
      for (auto k : clearSocktFds) {
        sseEmitterMap.erase(k);
      }
      id++;
    }
  });
  t.detach();
  svr.listen("0.0.0.0", HTTP_SERVER_PORT);
  return 0;
}
