#include <httplib.h>
#include <iostream>

using namespace httplib;

const auto html = R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebSocket Demo</title>
<style>
  body { font-family: monospace; margin: 2em; }
  #log { height: 300px; overflow-y: scroll; border: 1px solid #ccc; padding: 8px; }
  .controls { margin: 8px 0; }
  button { margin-right: 4px; }
</style>
</head>
<body>
<h1>WebSocket Demo</h1>
<p>Server accepts subprotocols: <b>echo</b>, <b>chat</b> (or none)</p>

<div class="controls">
  <label>Subprotocols: </label>
  <input id="protos" type="text" value="echo, chat" placeholder="leave empty for none" />
  <button onclick="doConnect()">Connect</button>
  <button onclick="doDisconnect()">Disconnect</button>
</div>

<div class="controls">
  <input id="msg" type="text" placeholder="Type a message..." />
  <button onclick="doSend()">Send</button>
</div>

<div class="controls">
  <button onclick="startAuto()">Start Auto (1s)</button>
  <button onclick="stopAuto()">Stop Auto</button>
  <span id="auto-status"></span>
</div>

<pre id="log"></pre>

<script>
var sock = null;
var logEl = document.getElementById("log");
var statusEl = document.getElementById("auto-status");
var timer = null;
var seq = 0;

function appendLog(text) {
  logEl.textContent += text + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

function doConnect() {
  if (sock && sock.readyState <= 1) { sock.close(); }
  var input = document.getElementById("protos").value.trim();
  var protocols = input ? input.split(/\s*,\s*/).filter(Boolean) : [];
  sock = new WebSocket("ws://" + location.host + "/ws", protocols);
  appendLog("[connecting] proposed: " + (protocols.length ? protocols.join(", ") : "(none)"));
  sock.onopen = function() { appendLog("[connected] subprotocol: " + (sock.protocol || "(none)")); };
  sock.onclose = function() { appendLog("[disconnected]"); stopAuto(); };
  sock.onmessage = function(e) { appendLog("< " + e.data); };
}

function doDisconnect() {
  if (sock) { sock.close(); }
}

function doSend() {
  var input = document.getElementById("msg");
  if (!sock || sock.readyState !== 1 || input.value === "") return;
  sock.send(input.value);
  appendLog("> " + input.value);
  input.value = "";
}

function startAuto() {
  if (timer || !sock || sock.readyState !== 1) return;
  seq = 0;
  statusEl.textContent = "running...";
  timer = setInterval(function() {
    if (!sock || sock.readyState !== 1) { stopAuto(); return; }
    var msg = "auto #" + seq++;
    sock.send(msg);
    appendLog("> " + msg);
  }, 1000);
}

function stopAuto() {
  if (timer) { clearInterval(timer); timer = null; }
  statusEl.textContent = "";
}

document.getElementById("msg").addEventListener("keydown", function(e) {
  if (e.key === "Enter") doSend();
});

doConnect();
</script>
</body>
</html>
)HTML";

int main(void) {
  Server svr;

  svr.Get("/", [&](const Request & /*req*/, Response &res) {
    res.set_content(html, "text/html");
  });

  svr.WebSocket(
      "/ws",
      [](const Request &req, ws::WebSocket &ws) {
        std::cout << "WebSocket connected from " << req.remote_addr
                  << std::endl;

        std::string msg;
        while (ws.read(msg)) {
          std::cout << "Received: " << msg << std::endl;
          ws.send("echo: " + msg);
        }

        std::cout << "WebSocket disconnected" << std::endl;
      },
      [](const std::vector<std::string> &protocols) -> std::string {
        for (const auto &p : protocols) {
          if (p == "echo" || p == "chat") { return p; }
        }
        return "";
      });

  std::cout << "Listening on http://localhost:8080" << std::endl;
  svr.listen("localhost", 8080);
}
