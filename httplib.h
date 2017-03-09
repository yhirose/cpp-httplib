//
//  httplib.h
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#ifndef _CPPHTTPLIB_HTTPSLIB_H_
#define _CPPHTTPLIB_HTTPSLIB_H_

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#ifndef SO_SYNCHRONOUS_NONALERT
#define SO_SYNCHRONOUS_NONALERT 0x20
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif
#if (_MSC_VER < 1900)
#define snprintf _snprintf_s
#endif

#define S_ISREG(m)  (((m)&S_IFREG)==S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFDIR)==S_IFDIR)

#include <fcntl.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#undef min
#undef max

typedef SOCKET socket_t;
#else
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef int socket_t;
#endif

#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <sys/stat.h>
#include <assert.h>

namespace httplib
{

typedef std::map<std::string, std::string>      Map;
typedef std::multimap<std::string, std::string> MultiMap;
typedef std::smatch                             Match;

struct Request {
    std::string method;
    std::string url;
    MultiMap    headers;
    std::string body;
    Map         params;
    Match       matches;

    bool has_header(const char* key) const;
    std::string get_header_value(const char* key) const;
    void set_header(const char* key, const char* val);

    bool has_param(const char* key) const;
};

struct Response {
    int         status;
    MultiMap    headers;
    std::string body;

    bool has_header(const char* key) const;
    std::string get_header_value(const char* key) const;
    void set_header(const char* key, const char* val);

    void set_redirect(const char* url);
    void set_content(const char* s, size_t n, const char* content_type);
    void set_content(const std::string& s, const char* content_type);

    Response() : status(-1) {}
};

class Server {
public:
    typedef std::function<void (const Request&, Response&)> Handler;
    typedef std::function<void (const Request&, const Response&)> Logger;

    Server();

    void get(const char* pattern, Handler handler);
    void post(const char* pattern, Handler handler);

    bool set_base_dir(const char* path);

    void set_error_handler(Handler handler);
    void set_logger(Logger logger);

    bool listen(const char* host, int port);
    void stop();

private:
    typedef std::vector<std::pair<std::regex, Handler>> Handlers;

    void process_request(socket_t sock);
    bool read_request_line(socket_t sock, Request& req);
    bool routing(Request& req, Response& res);
    bool handle_file_request(Request& req, Response& res);
    bool dispatch_request(Request& req, Response& res, Handlers& handlers);

    socket_t    svr_sock_;
    std::string base_dir_;
    Handlers    get_handlers_;
    Handlers    post_handlers_;
    Handler     error_handler_;
    Logger      logger_;
};

class Client {
public:
    Client(const char* host, int port);

    std::shared_ptr<Response> get(const char* url);
    std::shared_ptr<Response> head(const char* url);
    std::shared_ptr<Response> post(const char* url, const std::string& body, const char* content_type);
    std::shared_ptr<Response> post(const char* url, const Map& params);

    bool send(const Request& req, Response& res);

private:
    bool read_response_line(socket_t sock, Response& res);

    const std::string host_;
    const int         port_;
};

// Implementation
namespace detail {

template <class Fn>
void split(const char* b, const char* e, char d, Fn fn)
{
    int i = 0;
    int beg = 0;

    while (e ? (b + i != e) : (b[i] != '\0')) {
        if (b[i] == d) {
            fn(&b[beg], &b[i]);
            beg = i + 1;
        }
        i++;
    }

    if (i) {
        fn(&b[beg], &b[i]);
    }
}

inline int socket_read(socket_t sock, char* ptr, size_t size)
{
    return recv(sock, ptr, size, 0);
}

inline int socket_write(socket_t sock, const char* ptr, size_t size)
{
    return send(sock, ptr, size, 0);
}

inline int socket_write(socket_t sock, const char* ptr)
{
    size_t size = strlen(ptr);
    return socket_write(sock, ptr, size);
}

inline bool socket_gets(socket_t sock, char* buf, int bufsiz)
{
    // TODO: buffering for better performance
    size_t i = 0;

    for (;;) {
        char byte;
        auto n = socket_read(sock, &byte, 1);

        if (n < 1) {
            if (i == 0) {
                return false;
            } else {
                break;
            }
        }

        buf[i++] = byte;

        if (byte == '\n') {
            break;
        }
    }

    buf[i] = '\0';
    return true;
}

template <typename ...Args>
inline void socket_printf(socket_t sock, const char* fmt, const Args& ...args)
{
    char buf[BUFSIZ];
    auto n = snprintf(buf, BUFSIZ, fmt, args...);
    if (n > 0) {
        if (n >= BUFSIZ) {
            // TODO: buffer size is not large enough...
        } else {
            socket_write(sock, buf, n);
        }
    }
}

inline int close_socket(socket_t sock)
{
#ifdef _MSC_VER
    return closesocket(sock);
#else
    return close(sock);
#endif
}

template <typename T>
inline bool read_and_close_socket(socket_t sock, T callback)
{
    auto ret = callback(sock);
    close_socket(sock);
    return ret;
}

inline int shutdown_socket(socket_t sock)
{
#ifdef _MSC_VER
    return shutdown(sock, SD_BOTH);
#else
    return shutdown(sock, SHUT_RDWR);
#endif
}

template <typename Fn>
socket_t create_socket(const char* host, int port, Fn fn)
{
#ifdef _MSC_VER
    int opt = SO_SYNCHRONOUS_NONALERT;
    setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char*)&opt, sizeof(opt));
#endif

    // Get address info
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    auto service = std::to_string(port);

    if (getaddrinfo(host, service.c_str(), &hints, &result)) {
        return -1;
    }

    for (auto rp = result; rp; rp = rp->ai_next) {
       // Create a socket
       auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
       if (sock == -1) {
          continue;
       }

       // Make 'reuse address' option available
       int yes = 1;
       setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

       // bind or connect
       if (fn(sock, *rp)) {
          freeaddrinfo(result);
          return sock;
       }

       close_socket(sock);
    }

    freeaddrinfo(result);
    return -1;
}

inline socket_t create_server_socket(const char* host, int port)
{
    return create_socket(host, port, [](socket_t sock, struct addrinfo& ai) -> socket_t {
        if (::bind(sock, ai.ai_addr, ai.ai_addrlen)) {
              return false;
        }
        if (listen(sock, 5)) { // Listen through 5 channels
            return false;
        }
        return true;
    });
}

inline socket_t create_client_socket(const char* host, int port)
{
    return create_socket(host, port, [](socket_t sock, struct addrinfo& ai) -> socket_t {
        if (connect(sock, ai.ai_addr, ai.ai_addrlen)) {
            return false;
        }
        return true;
    });
}

inline bool is_file(const std::string& s)
{
    struct stat st;
    return stat(s.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string& s)
{
    struct stat st;
    return stat(s.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

inline void read_file(const std::string& path, std::string& out)
{
    std::ifstream fs(path, std::ios_base::binary);
    fs.seekg(0, std::ios_base::end);
    auto size = fs.tellg();
    fs.seekg(0);
    out.resize(static_cast<size_t>(size));
    fs.read(&out[0], size);
}

inline std::string get_file_extention(const std::string& path)
{
    std::smatch m;
    auto pat = std::regex("\\.([a-zA-Z0-9]+)$");
    auto ret = std::regex_search(path, m, pat);
    std::string content_type;
    if (ret) {
        return m[1].str();
    }
    return std::string();
}

inline const char* get_content_type_from_file_extention(const std::string& ext)
{
    if (ext == "html") {
        return "text/html";
    }
    return "text/plain";
}

inline const char* status_message(int status)
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    default:
        case 500: return "Internal Server Error";
    }
}

inline const char* get_header_value(const MultiMap& map, const char* key, const char* def)
{
    auto it = map.find(key);
    if (it != map.end()) {
        return it->second.c_str();
    }
    return def;
}

inline int get_header_value_int(const MultiMap& map, const char* key, int def)
{
    auto it = map.find(key);
    if (it != map.end()) {
        return std::stoi(it->second);
    }
    return def;
}

inline bool read_headers(socket_t sock, MultiMap& headers)
{
    static std::regex re("(.+?): (.+?)\r\n");

    const auto BUFSIZ_HEADER = 2048;
    char buf[BUFSIZ_HEADER];

    for (;;) {
        if (!socket_gets(sock, buf, BUFSIZ_HEADER)) {
            return false;
        }
        if (!strcmp(buf, "\r\n")) {
            break;
        }
        std::cmatch m;
        if (std::regex_match(buf, m, re)) {
            auto key = std::string(m[1]);
            auto val = std::string(m[2]);
            headers.insert(std::make_pair(key, val));
        }
    }

    return true;
}

template <typename T>
bool read_content(socket_t sock, T& x)
{
    auto len = get_header_value_int(x.headers, "Content-Length", 0);
    if (len) {
        x.body.assign(len, 0);
        if (!socket_read(sock, &x.body[0], x.body.size())) {
            return false;
        }
    }
    return true;
}

template <typename T>
inline void write_headers(socket_t sock, const T& res)
{
    socket_write(sock, "Connection: close\r\n");

    for (const auto& x: res.headers) {
        if (x.first != "Content-Type" && x.first != "Content-Length") {
            socket_printf(sock, "%s: %s\r\n", x.first.c_str(), x.second.c_str());
        }
    }

    auto t = get_header_value(res.headers, "Content-Type", "text/plain");
    socket_printf(sock, "Content-Type: %s\r\n", t);
    socket_printf(sock, "Content-Length: %ld\r\n", res.body.size());
    socket_write(sock, "\r\n");
}

inline void write_response(socket_t sock, const Request& req, const Response& res)
{
    socket_printf(sock, "HTTP/1.0 %d %s\r\n", res.status, status_message(res.status));

    write_headers(sock, res);

    if (!res.body.empty() && req.method != "HEAD") {
        socket_write(sock, res.body.c_str(), res.body.size());
    }
}

inline std::string encode_url(const std::string& s)
{
    std::string result;

    for (auto i = 0; s[i]; i++) {
        switch (s[i]) {
        case ' ':  result += "+"; break;
        case '\'': result += "%27"; break;
        case ',':  result += "%2C"; break;
        case ':':  result += "%3A"; break;
        case ';':  result += "%3B"; break;
        default:
            if (s[i] < 0) {
                result += '%';
                char hex[4];
                size_t len = snprintf(hex, sizeof(hex), "%02X", (unsigned char)s[i]);
                assert(len == 2);
                result.append(hex, len);
            } else {
                result += s[i];
            }
            break;
        }
   }

    return result;
}

inline bool is_hex(char c, int& v)
{
    if (0x20 <= c && isdigit(c)) {
        v = c - '0';
        return true;
    } else if ('A' <= c && c <= 'F') {
        v = c - 'A' + 10;
        return true;
    } else if ('a' <= c && c <= 'f') {
        v = c - 'a' + 10;
        return true;
    }
    return false;
}

inline int from_hex_to_i(const std::string& s, int i, int cnt, int& val)
{
    val = 0;
    for (; s[i] && cnt; i++, cnt--) {
        int v = 0;
        if (is_hex(s[i], v)) {
            val = val * 16 + v;
        } else {
            break;
        }
    }
    return --i;
}

inline size_t to_utf8(int code, char* buff)
{
    if (code < 0x0080) {
        buff[0] = (code & 0x7F);
        return 1;
    } else if (code < 0x0800) {
        buff[0] = (0xC0 | ((code >> 6) & 0x1F));
        buff[1] = (0x80 | (code & 0x3F));
        return 2;
    } else if (code < 0xD800) {
        buff[0] = (0xE0 | ((code >> 12) & 0xF));
        buff[1] = (0x80 | ((code >> 6) & 0x3F));
        buff[2] = (0x80 | (code & 0x3F));
        return 3;
    } else if (code < 0xE000)  { // D800 - DFFF is invalid...
        return 0;
    } else if (code < 0x10000) {
        buff[0] = (0xE0 | ((code >> 12) & 0xF));
        buff[1] = (0x80 | ((code >> 6) & 0x3F));
        buff[2] = (0x80 | (code & 0x3F));
        return 3;
    } else if (code < 0x110000) {
        buff[0] = (0xF0 | ((code >> 18) & 0x7));
        buff[1] = (0x80 | ((code >> 12) & 0x3F));
        buff[2] = (0x80 | ((code >> 6) & 0x3F));
        buff[3] = (0x80 | (code & 0x3F));
        return 4;
    }

    // NOTREACHED
    return 0;
}

inline std::string decode_url(const std::string& s)
{
    std::string result;

    for (int i = 0; s[i]; i++) {
        if (s[i] == '%') {
            i++;
            assert(s[i]);

            if (s[i] == '%') {
                result += s[i];
            } else if (s[i] == 'u') {
                // Unicode
                i++;
                assert(s[i]);

                int val = 0;
                i = from_hex_to_i(s, i, 4, val);

                char buff[4];
                size_t len = to_utf8(val, buff);

                if (len > 0) {
                    result.append(buff, len);
                }
            } else {
                // HEX
                int val = 0;
                i = from_hex_to_i(s, i, 2, val);
                result += val;
            }
        } else if (s[i] == '+') {
            result += ' ';
        } else {
            result += s[i];
        }
    }

    return result;
}

inline void write_request(socket_t sock, const Request& req)
{
    auto url = encode_url(req.url);
    socket_printf(sock, "%s %s HTTP/1.0\r\n", req.method.c_str(), url.c_str());

    write_headers(sock, req);

    if (!req.body.empty()) {
        if (req.has_header("application/x-www-form-urlencoded")) {
            auto str = encode_url(req.body);
            socket_write(sock, str.c_str(), str.size());
        } else {
            socket_write(sock, req.body.c_str(), req.body.size());
        }
    }
}

inline void parse_query_text(const std::string& s, Map& params)
{
    split(&s[0], &s[s.size()], '&', [&](const char* b, const char* e) {
        std::string key;
        std::string val;
        split(b, e, '=', [&](const char* b, const char* e) {
            if (key.empty()) {
                key.assign(b, e);
            } else {
                val.assign(b, e);
            }
        });
        params[key] = detail::decode_url(val);
    });
}

#ifdef _MSC_VER
class WSInit {
public:
    WSInit() {
        WSADATA wsaData;
        WSAStartup(0x0002, &wsaData);
    }

    ~WSInit() {
        WSACleanup();
    }
};

static WSInit wsinit_;
#endif

} // namespace detail

// Request implementation
inline bool Request::has_header(const char* key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Request::get_header_value(const char* key) const
{
    return detail::get_header_value(headers, key, "");
}

inline void Request::set_header(const char* key, const char* val)
{
    headers.insert(std::make_pair(key, val));
}

inline bool Request::has_param(const char* key) const
{
    return params.find(key) != params.end();
}

// Response implementation
inline bool Response::has_header(const char* key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Response::get_header_value(const char* key) const
{
    return detail::get_header_value(headers, key, "");
}

inline void Response::set_header(const char* key, const char* val)
{
    headers.insert(std::make_pair(key, val));
}

inline void Response::set_redirect(const char* url)
{
    set_header("Location", url);
    status = 302;
}

inline void Response::set_content(const char* s, size_t n, const char* content_type)
{
    body.assign(s, n);
    set_header("Content-Type", content_type);
}

inline void Response::set_content(const std::string& s, const char* content_type)
{
    body = s;
    set_header("Content-Type", content_type);
}

// HTTP server implementation
inline Server::Server()
    : svr_sock_(-1)
{
}

inline void Server::get(const char* pattern, Handler handler)
{
    get_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
}

inline void Server::post(const char* pattern, Handler handler)
{
    post_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
}

inline bool Server::set_base_dir(const char* path)
{
    if (detail::is_dir(path)) {
        base_dir_ = path;
        return true;
    }
    return false;
}

inline void Server::set_error_handler(Handler handler)
{
    error_handler_ = handler;
}

inline void Server::set_logger(Logger logger)
{
    logger_ = logger;
}

inline bool Server::listen(const char* host, int port)
{
    svr_sock_ = detail::create_server_socket(host, port);
    if (svr_sock_ == -1) {
        return false;
    }

    auto ret = true;

    for (;;) {
        socket_t sock = accept(svr_sock_, NULL, NULL);

        if (sock == -1) {
            if (svr_sock_ != -1) {
                detail::close_socket(svr_sock_);
                ret = false;
            } else {
                ; // The server socket was closed by user.
            }
            break;
        }

        // TODO: should be async
        detail::read_and_close_socket(sock, [this](socket_t sock) {
            process_request(sock);
            return true;
        });
    }

    return ret;
}

inline void Server::stop()
{
    detail::shutdown_socket(svr_sock_);
    detail::close_socket(svr_sock_);
    svr_sock_ = -1;
}

inline bool Server::read_request_line(socket_t sock, Request& req)
{
    const auto BUFSIZ_REQUESTLINE = 2048;
    char buf[BUFSIZ_REQUESTLINE];
    if (!detail::socket_gets(sock, buf, BUFSIZ_REQUESTLINE)) {
        return false;
    }

    static std::regex re("(GET|HEAD|POST) ([^?]+)(?:\\?(.+?))? HTTP/1\\.[01]\r\n");

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        req.method = std::string(m[1]);
        req.url = detail::decode_url(m[2]);

        // Parse query text
        auto len = std::distance(m[3].first, m[3].second);
        if (len > 0) {
            detail::parse_query_text(m[3], req.params);
        }

        return true;
    }

    return false;
}

inline bool Server::handle_file_request(Request& req, Response& res)
{
    if (!base_dir_.empty()) {
        std::string path = base_dir_ + req.url;

        if (!path.empty() && path.back() == '/') {
            path += "index.html";
        }

        if (detail::is_file(path)) {
            detail::read_file(path, res.body);
            res.set_header("Content-Type", 
                detail::get_content_type_from_file_extention(
                    detail::get_file_extention(path)));
            res.status = 200;
            return true;
        }
    }

    return false;
}

inline bool Server::routing(Request& req, Response& res)
{
    if (req.method == "GET" && handle_file_request(req, res)) {
        return true;
    }

    if (req.method == "GET" || req.method == "HEAD") {
        return dispatch_request(req, res, get_handlers_);
    } else if (req.method == "POST") {
        return dispatch_request(req, res, post_handlers_);
    }
    return false;
}

inline bool Server::dispatch_request(Request& req, Response& res, Handlers& handlers)
{
    for (const auto& x: handlers) {
        const auto& pattern = x.first;
        const auto& handler = x.second;

        if (std::regex_match(req.url, req.matches, pattern)) {
            handler(req, res);
            return true;
        }
    }
    return false;
}

inline void Server::process_request(socket_t sock)
{
    Request req;
    Response res;

    if (!read_request_line(sock, req) ||
        !detail::read_headers(sock, req.headers)) {
        return;
    }

    if (req.method == "POST") {
        if (!detail::read_content(sock, req)) {
            return;
        }
        static std::string type = "application/x-www-form-urlencoded";
        if (!req.get_header_value("Content-Type").compare(0, type.size(), type)) {
            detail::parse_query_text(req.body, req.params);
        }
    }

    if (routing(req, res)) {
        if (res.status == -1) {
            res.status = 200;
        }
    } else {
        res.status = 404;
    }
    assert(res.status != -1);

    if (400 <= res.status && error_handler_) {
        error_handler_(req, res);
    }

    detail::write_response(sock, req, res);

    if (logger_) {
        logger_(req, res);
    }
}

// HTTP client implementation
inline Client::Client(const char* host, int port)
    : host_(host)
    , port_(port)
{
}

inline bool Client::read_response_line(socket_t sock, Response& res)
{
    const auto BUFSIZ_RESPONSELINE = 2048;
    char buf[BUFSIZ_RESPONSELINE];
    if (!detail::socket_gets(sock, buf, BUFSIZ_RESPONSELINE)) {
        return false;
    }

    const static std::regex re("HTTP/1\\.[01] (\\d+?) .+\r\n");

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        res.status = std::stoi(std::string(m[1]));
    }

    return true;
}

inline bool Client::send(const Request& req, Response& res)
{
    auto sock = detail::create_client_socket(host_.c_str(), port_);
    if (sock == -1) {
        return false;
    }

    return detail::read_and_close_socket(sock, [&](socket_t sock) {
        // Send request
        detail::write_request(sock, req);

        // Receive response
        if (!read_response_line(sock, res) ||
            !detail::read_headers(sock, res.headers)) {
            return false;
        }
        if (req.method != "HEAD") {
            if (!detail::read_content(sock, res)) {
                return false;
            }
        }

        return true;
    });
}

inline std::shared_ptr<Response> Client::get(const char* url)
{
    Request req;
    req.method = "GET";
    req.url = url;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::head(const char* url)
{
    Request req;
    req.method = "HEAD";
    req.url = url;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::post(
    const char* url, const std::string& body, const char* content_type)
{
    Request req;
    req.method = "POST";
    req.url = url;
    req.set_header("Content-Type", content_type);
    req.body = body;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::post(
    const char* url, const Map& params)
{
    std::string query;
    for (auto it = params.begin(); it != params.end(); ++it) {
        if (it != params.begin()) {
            query += "&";
        }
        query += it->first;
        query += "=";
        query += it->second;
    }

    return post(url, query, "application/x-www-form-urlencoded");
}

} // namespace httplib

#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
