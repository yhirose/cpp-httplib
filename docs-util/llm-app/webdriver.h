// webdriver.h — Thin W3C WebDriver client using cpp-httplib + nlohmann/json.
// SPDX-License-Identifier: MIT
//
// Usage:
//   webdriver::Session session;  // starts headless Firefox via geckodriver
//   session.navigate("http://localhost:8080");
//   auto el = session.css("h1");
//   assert(el.text() == "Hello!");
//   // session destructor closes the browser
#pragma once

#include "httplib.h"
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace webdriver {

using json = nlohmann::json;

// ─── Errors ──────────────────────────────────────────────────

class Error : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// ─── Forward declarations ────────────────────────────────────

class Session;

// ─── Element ─────────────────────────────────────────────────

class Element {
  friend class Session;

  httplib::Client *cli_;
  std::string session_id_;
  std::string element_id_;

public:
  Element(httplib::Client *cli, const std::string &session_id,
          const std::string &element_id)
      : cli_(cli), session_id_(session_id), element_id_(element_id) {}

  std::string url(const std::string &suffix = "") const {
    return "/session/" + session_id_ + "/element/" + element_id_ + suffix;
  }

public:
  std::string text() const {
    auto res = cli_->Get(url("/text"));
    if (!res || res->status != 200) {
      throw Error("Failed to get element text");
    }
    return json::parse(res->body)["value"].get<std::string>();
  }

  std::string attribute(const std::string &name) const {
    auto res = cli_->Get(url("/attribute/" + name));
    if (!res || res->status != 200) { return ""; }
    auto val = json::parse(res->body)["value"];
    return val.is_null() ? "" : val.get<std::string>();
  }

  std::string property(const std::string &name) const {
    auto res = cli_->Get(url("/property/" + name));
    if (!res || res->status != 200) { return ""; }
    auto val = json::parse(res->body)["value"];
    return val.is_null() ? "" : val.get<std::string>();
  }

  void click() const {
    auto res = cli_->Post(url("/click"), "{}", "application/json");
    if (!res || res->status != 200) { throw Error("Failed to click element"); }
  }

  void send_keys(const std::string &keys) const {
    json body = {{"text", keys}};
    auto res = cli_->Post(url("/value"), body.dump(), "application/json");
    if (!res || res->status != 200) {
      throw Error("Failed to send keys to element");
    }
  }

  void clear() const {
    auto res = cli_->Post(url("/clear"), "{}", "application/json");
    if (!res || res->status != 200) { throw Error("Failed to clear element"); }
  }

  std::string tag_name() const {
    auto res = cli_->Get(url("/name"));
    if (!res || res->status != 200) { throw Error("Failed to get tag name"); }
    return json::parse(res->body)["value"].get<std::string>();
  }

  bool is_displayed() const {
    auto res = cli_->Get(url("/displayed"));
    if (!res || res->status != 200) { return false; }
    return json::parse(res->body)["value"].get<bool>();
  }
};

// ─── Session ─────────────────────────────────────────────────

class Session {
  httplib::Client cli_;
  std::string session_id_;

  // W3C WebDriver uses this key for element references
  static constexpr const char *ELEMENT_KEY =
      "element-6066-11e4-a52e-4f735466cecf";

  std::string extract_element_id(const json &value) const {
    if (value.contains(ELEMENT_KEY)) {
      return value[ELEMENT_KEY].get<std::string>();
    }
    // Fallback: try "ELEMENT" (older protocol)
    if (value.contains("ELEMENT")) {
      return value["ELEMENT"].get<std::string>();
    }
    throw Error("No element identifier in response: " + value.dump());
  }

  std::string url(const std::string &suffix) const {
    return "/session/" + session_id_ + suffix;
  }

public:
  explicit Session(const std::string &host = "127.0.0.1", int port = 4444)
      : cli_(host, port) {
    cli_.set_read_timeout(std::chrono::seconds(30));
    cli_.set_connection_timeout(std::chrono::seconds(5));

    json caps = {
        {"capabilities",
         {{"alwaysMatch",
           {{"moz:firefoxOptions", {{"args", json::array({"-headless"})}}}}}}}};

    auto res = cli_.Post("/session", caps.dump(), "application/json");
    if (!res) { throw Error("Cannot connect to geckodriver"); }
    if (res->status != 200) {
      throw Error("Failed to create session: " + res->body);
    }

    auto body = json::parse(res->body);
    session_id_ = body["value"]["sessionId"].get<std::string>();
  }

  ~Session() {
    try {
      cli_.Delete(url(""));
    } catch (...) {}
  }

  // Non-copyable, non-movable (owns a session)
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  // ─── Navigation ──────────────────────────────────────────

  void navigate(const std::string &nav_url) {
    json body = {{"url", nav_url}};
    auto res = cli_.Post(url("/url"), body.dump(), "application/json");
    if (!res || res->status != 200) {
      throw Error("Failed to navigate to: " + nav_url);
    }
  }

  std::string title() {
    auto res = cli_.Get(url("/title"));
    if (!res || res->status != 200) { throw Error("Failed to get title"); }
    return json::parse(res->body)["value"].get<std::string>();
  }

  std::string current_url() {
    auto res = cli_.Get(url("/url"));
    if (!res || res->status != 200) {
      throw Error("Failed to get current URL");
    }
    return json::parse(res->body)["value"].get<std::string>();
  }

  // ─── Find elements ──────────────────────────────────────

  Element find(const std::string &using_, const std::string &value) {
    json body = {{"using", using_}, {"value", value}};
    auto res = cli_.Post(url("/element"), body.dump(), "application/json");
    if (!res || res->status != 200) {
      throw Error("Element not found: " + using_ + "=" + value);
    }
    auto eid = extract_element_id(json::parse(res->body)["value"]);
    return Element(&cli_, session_id_, eid);
  }

  std::vector<Element> find_all(const std::string &using_,
                                const std::string &value) {
    json body = {{"using", using_}, {"value", value}};
    auto res = cli_.Post(url("/elements"), body.dump(), "application/json");
    if (!res || res->status != 200) { return {}; }

    std::vector<Element> elements;
    for (auto &v : json::parse(res->body)["value"]) {
      elements.emplace_back(&cli_, session_id_, extract_element_id(v));
    }
    return elements;
  }

  // Convenience: find by CSS selector
  Element css(const std::string &selector) {
    return find("css selector", selector);
  }

  std::vector<Element> css_all(const std::string &selector) {
    return find_all("css selector", selector);
  }

  // ─── Wait ────────────────────────────────────────────────

  // Poll for an element until it appears or timeout
  Element wait_for(const std::string &selector, int timeout_ms = 5000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      try {
        return css(selector);
      } catch (...) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
    }
    throw Error("Timeout waiting for element: " + selector);
  }

  // Wait until a JS expression returns truthy
  bool wait_until(const std::string &script, int timeout_ms = 5000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      auto result = execute_script(script);
      if (result != "null" && result != "false" && result != "" &&
          result != "0" && result != "undefined") {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return false;
  }

  // ─── Execute script ─────────────────────────────────────

  std::string execute_script(const std::string &script,
                             const json &args = json::array()) {
    json body = {{"script", script}, {"args", args}};
    auto res = cli_.Post(url("/execute/sync"), body.dump(), "application/json");
    if (!res || res->status != 200) {
      throw Error("Failed to execute script: " + script);
    }
    auto val = json::parse(res->body)["value"];
    if (val.is_null()) { return "null"; }
    if (val.is_string()) { return val.get<std::string>(); }
    return val.dump();
  }

  // ─── Page source ────────────────────────────────────────

  std::string page_source() {
    auto res = cli_.Get(url("/source"));
    if (!res || res->status != 200) {
      throw Error("Failed to get page source");
    }
    return json::parse(res->body)["value"].get<std::string>();
  }
};

} // namespace webdriver
