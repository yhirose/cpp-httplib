//
//  ssecli-stream.cc
//
//  Copyright (c) 2026 Yuji Hirose. All rights reserved.
//  MIT License
//
//  SSE (Server-Sent Events) client example using Streaming API
//  with automatic reconnection support (similar to JavaScript's EventSource)
//

#include <httplib.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

//------------------------------------------------------------------------------
// SSE Event Parser
//------------------------------------------------------------------------------
// Parses SSE events from the stream according to the SSE specification.
// SSE format:
//   event: <event-type>     (optional, defaults to "message")
//   data: <payload>         (can have multiple lines)
//   id: <event-id>          (optional, used for reconnection)
//   retry: <milliseconds>   (optional, reconnection interval)
//   <blank line>            (signals end of event)
//
struct SSEEvent {
  std::string event = "message"; // Event type (default: "message")
  std::string data;              // Event payload
  std::string id;                // Event ID for Last-Event-ID header

  void clear() {
    event = "message";
    data.clear();
    id.clear();
  }
};

// Parse a single SSE field line (e.g., "data: hello")
// Returns true if this line ends an event (blank line)
bool parse_sse_line(const std::string &line, SSEEvent &event, int &retry_ms) {
  // Blank line signals end of event
  if (line.empty() || line == "\r") { return true; }

  // Find the colon separator
  auto colon_pos = line.find(':');
  if (colon_pos == std::string::npos) {
    // Line with no colon is treated as field name with empty value
    return false;
  }

  std::string field = line.substr(0, colon_pos);
  std::string value;

  // Value starts after colon, skip optional single space
  if (colon_pos + 1 < line.size()) {
    size_t value_start = colon_pos + 1;
    if (line[value_start] == ' ') { value_start++; }
    value = line.substr(value_start);
    // Remove trailing \r if present
    if (!value.empty() && value.back() == '\r') { value.pop_back(); }
  }

  // Handle known fields
  if (field == "event") {
    event.event = value;
  } else if (field == "data") {
    // Multiple data lines are concatenated with newlines
    if (!event.data.empty()) { event.data += "\n"; }
    event.data += value;
  } else if (field == "id") {
    // Empty id is valid (clears the last event ID)
    event.id = value;
  } else if (field == "retry") {
    // Parse retry interval in milliseconds
    try {
      retry_ms = std::stoi(value);
    } catch (...) {
      // Invalid retry value, ignore
    }
  }
  // Unknown fields are ignored per SSE spec

  return false;
}

//------------------------------------------------------------------------------
// Main - SSE Client with Auto-Reconnection
//------------------------------------------------------------------------------
int main(void) {
  // Configuration
  const std::string host = "http://localhost:1234";
  const std::string path = "/event1";

  httplib::Client cli(host);

  // State for reconnection (persists across connections)
  std::string last_event_id; // Sent as Last-Event-ID header on reconnect
  int retry_ms = 3000; // Reconnection delay (server can override via retry:)
  int connection_count = 0;

  std::cout << "SSE Client starting...\n";
  std::cout << "Target: " << host << path << "\n";
  std::cout << "Press Ctrl+C to exit\n\n";

  //----------------------------------------------------------------------------
  // Main reconnection loop
  // This mimics JavaScript's EventSource behavior:
  // - Automatically reconnects on connection failure
  // - Sends Last-Event-ID header to resume from last received event
  // - Respects server's retry interval
  //----------------------------------------------------------------------------
  while (true) {
    connection_count++;
    std::cout << "[Connection #" << connection_count << "] Connecting...\n";

    // Build headers, including Last-Event-ID if we have one
    httplib::Headers headers;
    if (!last_event_id.empty()) {
      headers.emplace("Last-Event-ID", last_event_id);
      std::cout << "[Connection #" << connection_count
                << "] Resuming from event ID: " << last_event_id << "\n";
    }

    // Open streaming connection
    auto result = httplib::stream::Get(cli, path, headers);

    //--------------------------------------------------------------------------
    // Connection error handling
    //--------------------------------------------------------------------------
    if (!result) {
      std::cerr << "[Connection #" << connection_count
                << "] Failed: " << httplib::to_string(result.error()) << "\n";
      std::cerr << "Reconnecting in " << retry_ms << "ms...\n\n";
      std::this_thread::sleep_for(std::chrono::milliseconds(retry_ms));
      continue;
    }

    if (result.status() != 200) {
      std::cerr << "[Connection #" << connection_count
                << "] HTTP error: " << result.status() << "\n";

      // For certain errors, don't reconnect
      if (result.status() == 204 || // No Content - server wants us to stop
          result.status() == 404 || // Not Found
          result.status() == 401 || // Unauthorized
          result.status() == 403) { // Forbidden
        std::cerr << "Permanent error, not reconnecting.\n";
        return 1;
      }

      std::cerr << "Reconnecting in " << retry_ms << "ms...\n\n";
      std::this_thread::sleep_for(std::chrono::milliseconds(retry_ms));
      continue;
    }

    // Verify Content-Type (optional but recommended)
    auto content_type = result.get_header_value("Content-Type");
    if (content_type.find("text/event-stream") == std::string::npos) {
      std::cerr << "[Warning] Content-Type is not text/event-stream: "
                << content_type << "\n";
    }

    std::cout << "[Connection #" << connection_count << "] Connected!\n\n";

    //--------------------------------------------------------------------------
    // Event receiving loop
    // Reads chunks from the stream and parses SSE events
    //--------------------------------------------------------------------------
    std::string buffer;
    SSEEvent current_event;
    int event_count = 0;

    // Read data from stream using httplib::stream API
    while (result.next()) {
      buffer.append(result.data(), result.size());

      // Process complete lines in the buffer
      size_t line_start = 0;
      size_t newline_pos;

      while ((newline_pos = buffer.find('\n', line_start)) !=
             std::string::npos) {
        std::string line = buffer.substr(line_start, newline_pos - line_start);
        line_start = newline_pos + 1;

        // Parse the line and check if event is complete
        bool event_complete = parse_sse_line(line, current_event, retry_ms);

        if (event_complete && !current_event.data.empty()) {
          // Event received - process it
          event_count++;

          std::cout << "--- Event #" << event_count << " ---\n";
          std::cout << "Type: " << current_event.event << "\n";
          std::cout << "Data: " << current_event.data << "\n";
          if (!current_event.id.empty()) {
            std::cout << "ID:   " << current_event.id << "\n";
          }
          std::cout << "\n";

          // Update last_event_id for reconnection
          // Note: Empty id clears the last event ID per SSE spec
          if (!current_event.id.empty()) { last_event_id = current_event.id; }

          current_event.clear();
        }
      }

      // Keep unprocessed data in buffer
      buffer.erase(0, line_start);
    }

    //--------------------------------------------------------------------------
    // Connection ended - check why
    //--------------------------------------------------------------------------
    if (result.read_error() != httplib::Error::Success) {
      std::cerr << "\n[Connection #" << connection_count
                << "] Error: " << httplib::to_string(result.read_error())
                << "\n";
    } else {
      std::cout << "\n[Connection #" << connection_count
                << "] Stream ended normally\n";
    }

    std::cout << "Received " << event_count << " events in this connection\n";
    std::cout << "Reconnecting in " << retry_ms << "ms...\n\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(retry_ms));
  }

  return 0;
}
