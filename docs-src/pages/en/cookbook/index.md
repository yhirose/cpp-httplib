---
title: "Cookbook"
order: 0
---

A collection of recipes that answer "How do I...?" questions. Each recipe is self-contained — read only what you need.

## Client

### Basics
- Get the response body as a string / save to a file
- Send and receive JSON
- Set default headers (`set_default_headers`)
- Follow redirects (`set_follow_location`)

### Authentication
- Use Basic authentication (`set_basic_auth`)
- Call an API with a Bearer token

### File Upload
- Upload a file as multipart form data (`make_file_provider`)
- POST a file as raw binary (`make_file_body`)
- Send the body with chunked transfer (Content Provider)

### Streaming & Progress
- Receive a response as a stream
- Use the progress callback (`set_progress`)

### Connection & Performance
- Set timeouts (`set_connection_timeout` / `set_read_timeout`)
- Set an overall timeout (`set_max_timeout`)
- Understand connection reuse and Keep-Alive behavior
- Enable compression (`set_compress` / `set_decompress`)
- Send requests through a proxy (`set_proxy`)

### Error Handling & Debugging
- Handle error codes (`Result::error()`)
- Handle SSL errors (`ssl_error()` / `ssl_backend_error()`)
- Set up client logging (`set_logger` / `set_error_logger`)

## Server

### Basics
- Register GET / POST / PUT / DELETE handlers
- Receive JSON requests and return JSON responses
- Use path parameters (`/users/:id`)
- Set up a static file server (`set_mount_point`)

### Streaming & Files
- Stream a large file in the response (`ContentProvider`)
- Return a file download response (`Content-Disposition`)
- Receive multipart data as a stream (`ContentReader`)
- Compress responses (gzip)

### Handler Chain
- Add pre-processing to all routes (Pre-routing handler)
- Add response headers with a Post-routing handler (CORS, etc.)
- Authenticate per route with a Pre-request handler (`matched_route`)
- Pass data between handlers with `res.user_data`

### Error Handling & Debugging
- Return custom error pages (`set_error_handler`)
- Catch exceptions (`set_exception_handler`)
- Log requests (Logger)
- Detect client disconnection (`req.is_connection_closed()`)

### Operations & Tuning
- Assign a port dynamically (`bind_to_any_port`)
- Control startup order with `listen_after_bind`
- Shut down gracefully (`stop()` and signal handling)
- Tune Keep-Alive (`set_keep_alive_max_count` / `set_keep_alive_timeout`)
- Configure the thread pool (`new_task_queue`)

## TLS / Security

- Choosing between OpenSSL, mbedTLS, and wolfSSL (build-time `#define` differences)
- Control SSL certificate verification (disable, custom CA, custom callback)
- Use a custom certificate verification callback (`set_server_certificate_verifier`)
- Set up an SSL/TLS server (certificate and private key)
- Configure mTLS (mutual TLS with client certificates)
- Access the peer certificate on the server (`req.peer_cert()` / SNI)

## SSE

- Implement an SSE server
- Use event names to distinguish event types
- Handle reconnection (`Last-Event-ID`)
- Receive SSE events on the client

## WebSocket

- Implement a WebSocket echo server and client
- Configure heartbeats (`set_websocket_ping_interval`)
- Handle connection close
- Send and receive binary frames
