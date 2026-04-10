---
title: "Cookbook"
order: 0
status: "draft"
---

A collection of recipes that answer "How do I...?" questions. Each recipe is self-contained — read only what you need. For an introduction to the basics, see the [Tour](../tour/).

## Client

### Basics
- [C01. Get the response body / save to a file](c01-get-response-body)
- [C02. Send and receive JSON](c02-json)
- [C03. Set default headers](c03-default-headers)
- [C04. Follow redirects](c04-follow-location)

### Authentication
- [C05. Use Basic authentication](c05-basic-auth)
- [C06. Call an API with a Bearer token](c06-bearer-token)

### File Upload
- [C07. Upload a file as multipart form data](c07-multipart-upload)
- [C08. POST a file as raw binary](c08-post-file-body)
- [C09. Send the body with chunked transfer](c09-chunked-upload)

### Streaming & Progress
- [C10. Receive a response as a stream](c10-stream-response)
- [C11. Use the progress callback](c11-progress-callback)

### Connection & Performance
- [C12. Set timeouts](c12-timeouts)
- [C13. Set an overall timeout](c13-max-timeout)
- [C14. Understand connection reuse and Keep-Alive behavior](c14-keep-alive)
- [C15. Enable compression](c15-compression)
- [C16. Send requests through a proxy](c16-proxy)

### Error Handling & Debugging
- [C17. Handle error codes](c17-error-codes)
- [C18. Handle SSL errors](c18-ssl-errors)
- [C19. Set up client logging](c19-client-logger)

## Server

### Basics
- S01. Register GET / POST / PUT / DELETE handlers
- S02. Receive JSON requests and return JSON responses
- S03. Use path parameters (`/users/:id`)
- S04. Set up a static file server (`set_mount_point`)

### Streaming & Files
- S05. Stream a large file in the response (`ContentProvider`)
- S06. Return a file download response (`Content-Disposition`)
- S07. Receive multipart data as a stream (`ContentReader`)
- S08. Compress responses (gzip)

### Handler Chain
- S09. Add pre-processing to all routes (Pre-routing handler)
- S10. Add response headers with a Post-routing handler (CORS, etc.)
- S11. Authenticate per route with a Pre-request handler (`matched_route`)
- S12. Pass data between handlers with `res.user_data`

### Error Handling & Debugging
- S13. Return custom error pages (`set_error_handler`)
- S14. Catch exceptions (`set_exception_handler`)
- S15. Log requests (Logger)
- S16. Detect client disconnection (`req.is_connection_closed()`)

### Operations & Tuning
- S17. Assign a port dynamically (`bind_to_any_port`)
- S18. Control startup order with `listen_after_bind`
- S19. Shut down gracefully (`stop()` and signal handling)
- S20. Tune Keep-Alive (`set_keep_alive_max_count` / `set_keep_alive_timeout`)
- S21. Configure the thread pool (`new_task_queue`)
- S22. Communicate over Unix domain sockets (`set_address_family(AF_UNIX)`)

## TLS / Security

- T01. Choosing between OpenSSL, mbedTLS, and wolfSSL (build-time `#define` differences)
- T02. Control SSL certificate verification (disable, custom CA, custom callback)
- T03. Set up an SSL/TLS server (certificate and private key)
- T04. Configure mTLS (mutual TLS with client certificates)
- T05. Access the peer certificate on the server (`req.peer_cert()` / SNI)

## SSE

- E01. Implement an SSE server
- E02. Use event names to distinguish event types
- E03. Handle reconnection (`Last-Event-ID`)
- E04. Receive SSE events on the client

## WebSocket

- W01. Implement a WebSocket echo server and client
- W02. Configure heartbeats (`set_websocket_ping_interval`)
- W03. Handle connection close
- W04. Send and receive binary frames
