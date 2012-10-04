//
//  httplib.h
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#ifndef HTTPSVRKIT_H
#define HTTPSVRKIT_H

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#ifndef SO_SYNCHRONOUS_NONALERT
#define SO_SYNCHRONOUS_NONALERT 0x20;
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif

#include <fcntl.h>
#include <io.h>
#include <winsock2.h>

typedef SOCKET socket_t;
#else
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef int socket_t;
#endif

#include <functional>
#include <map>
#include <regex>
#include <string>
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
    void set_content(const std::string& s, const char* content_type);

    Response() : status(-1) {}
};

struct Connection {
    Request  request;
    Response response;
};

class Server {
public:
    typedef std::function<void (Connection& c)> Handler;

    Server(const char* host, int port);
    ~Server();

    void get(const char* pattern, Handler handler);
    void post(const char* pattern, Handler handler);

    void set_error_handler(Handler handler);
    void set_logger(Handler logger);

    bool run();
    void stop();

private:
    typedef std::vector<std::pair<std::regex, Handler>> Handlers;

    void process_request(FILE* fp_read, FILE* fp_write);
    bool read_request_line(FILE* fp, Request& req);
    bool routing(Connection& c);
    bool dispatch_request(Connection& c, Handlers& handlers);

    const std::string host_;
    const int         port_;
    socket_t          sock_;

    Handlers get_handlers_;
    Handlers post_handlers_;
    Handler  error_handler_;
    Handler  logger_;
};

class Client {
public:
    Client(const char* host, int port);
    ~Client();

    bool get(const char* url, Response& res);
    bool post(const char* url, const std::string& body, const char* content_type, Response& res);
    bool send(const Request& req, Response& res);

    std::shared_ptr<Response> get(const char* url);
    std::shared_ptr<Response> post(const char* url, const std::string& body, const char* content_type);

private:
    bool read_response_line(FILE* fp, Response& res);

    const std::string host_;
    const int         port_;
};

// Implementation

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

inline void get_flie_pointers(int fd, FILE*& fp_read, FILE*& fp_write)
{
#ifdef _WIN32
    int osfhandle = _open_osfhandle(fd, _O_RDONLY);
    fp_read = fdopen(osfhandle, "rb");
    fp_write = fdopen(osfhandle, "wb");
#else
    fp_read = fdopen(fd, "rb");
    fp_write = fdopen(fd, "wb");
#endif
}

template <typename Fn>
socket_t create_socket(const char* host, int port, Fn fn)
{
#ifdef _WIN32
    int opt = SO_SYNCHRONOUS_NONALERT;
    setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char*)&opt, sizeof(opt));
#endif

    // Create a server socket
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return -1;
    }

    // Make 'reuse address' option available
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    // Get a host entry info
    struct hostent* hp;
    if (!(hp = gethostbyname(host))) {
        return -1;
    }

    // Bind the socket to the given address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    return fn(sock, addr);
}

inline socket_t create_server_socket(const char* host, int port)
{
    return create_socket(host, port, [](socket_t sock, struct sockaddr_in& addr) -> socket_t {

        if (::bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
            return -1;
        }

        // Listen through 5 channels
        if (listen(sock, 5)) {
            return -1;
        }

        return sock;
    });
}

inline int close_socket(socket_t sock)
{
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
    return closesocket(sock);
#else
    shutdown(sock, SHUT_RDWR);
    return close(sock);
#endif
}

inline socket_t create_client_socket(const char* host, int port)
{
    return create_socket(host, port,
            [](socket_t sock, struct sockaddr_in& addr) -> socket_t {

        if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in))) {
            return -1;
        }

        return sock;
    });
}

inline const char* status_message(int status)
{
    const char* s = NULL;

    switch (status) {
    case 400:
        s = "Bad Request";
        break;
    case 404:
        s = "Not Found";
        break;
    default:
        status = 500;
        s = "Internal Server Error";
        break;
    }

    return s;
}

inline const char* get_header_value_text(const MultiMap& map, const char* key, const char* def)
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
        return std::atoi(it->second.c_str());
    }
    return def;
}

inline bool read_headers(FILE* fp, MultiMap& headers)
{
    static std::regex re("(.+?): (.+?)\r\n");

    const size_t BUFSIZ_HEADER = 2048;
    char buf[BUFSIZ_HEADER];

    for (;;) {
        if (!fgets(buf, BUFSIZ_HEADER, fp)) {
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
bool read_content(T& x, FILE* fp)
{
    auto len = get_header_value_int(x.headers, "Content-Length", 0);
    if (len) {
        x.body.assign(len, 0);
        if (!fgets(&x.body[0], x.body.size() + 1, fp)) {
            return false;
        }
    }
    return true;
}

template <typename T>
inline void write_headers(FILE* fp, const T& x)
{
    fprintf(fp, "Connection: close\r\n");

    for (auto it = x.headers.begin(); it != x.headers.end(); ++it) {
        if (it->first != "Content-Type" && it->first != "Content-Length") {
            fprintf(fp, "%s: %s\r\n", it->first.c_str(), it->second.c_str());
        }
    }

    if (!x.body.empty()) {
        auto content_type = get_header_value_text(x.headers, "Content-Type", "text/plain");
        fprintf(fp, "Content-Type: %s\r\n", content_type);
        fprintf(fp, "Content-Length: %ld\r\n", x.body.size());
    }

    fprintf(fp, "\r\n");
}

inline void write_response(FILE* fp, const Response& res)
{
    fprintf(fp, "HTTP/1.0 %d %s\r\n", res.status, status_message(res.status));

    write_headers(fp, res);

    if (!res.body.empty()) {
        fprintf(fp, "%s", res.body.c_str());
    }
}

inline void write_request(FILE* fp, const Request& req)
{
    fprintf(fp, "%s %s HTTP/1.0\r\n", req.method.c_str(), req.url.c_str());

    write_headers(fp, req);

    if (!req.body.empty()) {
        fprintf(fp, "%s", req.body.c_str());
    }
}

inline void parse_query_text(const char* b, const char* e, Map& params)
{
    split(b, e, '&', [&](const char* b, const char* e) {
        std::string key;
        std::string val;
        split(b, e, '=', [&](const char* b, const char* e) {
            if (key.empty()) {
                key.assign(b, e);
            } else {
                val.assign(b, e);
            }
        });
        params[key] = val;
    });
}

// HTTP server implementation
inline bool Request::has_header(const char* key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Request::get_header_value(const char* key) const
{
    return get_header_value_text(headers, key, "");
}

inline void Request::set_header(const char* key, const char* val)
{
    headers.insert(std::make_pair(key, val));
}

inline bool Request::has_param(const char* key) const
{
    return params.find(key) != params.end();
}

inline bool Response::has_header(const char* key) const
{
    return headers.find(key) != headers.end();
}

inline std::string Response::get_header_value(const char* key) const
{
    return get_header_value_text(headers, key, "");
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

inline void Response::set_content(const std::string& s, const char* content_type)
{
    body = s;
    set_header("Content-Type", content_type);
}

inline Server::Server(const char* host, int port)
    : host_(host)
    , port_(port)
    , sock_(-1)
{
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(0x0002, &wsaData);
#endif
}

inline Server::~Server()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

inline void Server::get(const char* pattern, Handler handler)
{
    get_handlers_.push_back(std::make_pair(pattern, handler));
}

inline void Server::post(const char* pattern, Handler handler)
{
    post_handlers_.push_back(std::make_pair(pattern, handler));
}

inline void Server::set_error_handler(Handler handler)
{
    error_handler_ = handler;
}

inline void Server::set_logger(Handler logger)
{
    logger_ = logger;
}

inline bool Server::run()
{
    sock_ = create_server_socket(host_.c_str(), port_);
    if (sock_ == -1) {
        return false;
    }
    
    for (;;) {
        socket_t fd = accept(sock_, NULL, NULL);
        if (fd == -1) {
            // The server socket was closed by user.
            if (sock_ == -1) {
                return true;
            } 

            close_socket(sock_);
            return false;
        }

        FILE* fp_read;
        FILE* fp_write;
        get_flie_pointers(fd, fp_read, fp_write);

        process_request(fp_read, fp_write);

        fflush(fp_write);
        close_socket(fd);
    }

    // NOTREACHED
}

inline void Server::stop()
{
    close_socket(sock_);
    sock_ = -1;
}

inline bool Server::read_request_line(FILE* fp, Request& req)
{
    const size_t BUFSIZ_REQUESTLINE = 2048;
    char buf[BUFSIZ_REQUESTLINE];
    if (!fgets(buf, BUFSIZ_REQUESTLINE, fp)) {
        return false;
    }

    static std::regex re("(GET|POST) ([^?]+)(?:\\?(.+?))? HTTP/1\\.[01]\r\n");

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        req.method = std::string(m[1]);
        req.url = std::string(m[2]);

        // Parse query text
        auto len = std::distance(m[3].first, m[3].second);
        if (len > 0) {
            const auto& pos = m[3];
            parse_query_text(pos.first, pos.second, req.params);
        }

        return true;
    }

    return false;
}

inline bool Server::routing(Connection& c)
{
    if (c.request.method == "GET") {
        return dispatch_request(c, get_handlers_);
    } else if (c.request.method == "POST") {
        return dispatch_request(c, post_handlers_);
    }
    return false;
}

inline bool Server::dispatch_request(Connection& c, Handlers& handlers)
{
    for (auto it = handlers.begin(); it != handlers.end(); ++it) {
        const auto& pattern = it->first;
        const auto& handler = it->second;

        if (std::regex_match(c.request.url, c.request.matches, pattern)) {
            handler(c);
            return true;
        }
    }
    return false;
}

inline void Server::process_request(FILE* fp_read, FILE* fp_write)
{
    Connection c;
    auto& req = c.request;

    if (!read_request_line(fp_read, req) ||
        !read_headers(fp_read, req.headers)) {
        return;
    }

    if (req.method == "POST") {
        if (!read_content(req, fp_read)) {
            return;
        }
        if (req.get_header_value("Content-Type") == "application/x-www-form-urlencoded") {
            parse_query_text(&req.body[0], &req.body[req.body.size()], req.params);
        }
    }
    
    if (routing(c)) {
        if (c.response.status == -1) {
            c.response.status = 200;
        }
    } else {
        c.response.status = 404;
    }
    assert(c.response.status != -1);

    if (400 <= c.response.status && error_handler_) {
        error_handler_(c);
    }

    write_response(fp_write, c.response);

    if (logger_) {
        logger_(c);
    }
}

// HTTP client implementation
inline Client::Client(const char* host, int port)
    : host_(host)
    , port_(port)
{
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(0x0002, &wsaData);
#endif
}

inline Client::~Client()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

inline bool Client::read_response_line(FILE* fp, Response& res)
{
    const size_t BUFSIZ_RESPONSELINE = 2048;
    char buf[BUFSIZ_RESPONSELINE];
    if (!fgets(buf, BUFSIZ_RESPONSELINE, fp)) {
        return false;
    }

    static std::regex re("HTTP/1\\.[01] (\\d+?) .+\r\n");

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        res.status = std::atoi(std::string(m[1]).c_str());
    }

    return true;
}

inline bool Client::get(const char* url, Response& res)
{
    Request req;
    req.method = "GET";
    req.url = url;
    return send(req, res);
}

inline bool Client::post(
    const char* url, const std::string& body, const char* content_type, Response& res)
{
    Request req;
    req.method = "POST";
    req.url = url;
    req.set_header("Content-Type", content_type);
    req.body = body;
    return send(req, res);
}

inline bool Client::send(const Request& req, Response& res)
{
    socket_t sock = create_client_socket(host_.c_str(), port_);
    if (sock == -1) {
        return false;
    }

    FILE* fp_read;
    FILE* fp_write;
    get_flie_pointers(sock, fp_read, fp_write);

    // Send request
    write_request(fp_write, req);
    fflush(fp_write);

    if (!read_response_line(fp_read, res) ||
        !read_headers(fp_read, res.headers) ||
        !read_content(res, fp_read)) {
        return false;
    }

    close_socket(sock);

    return true;
}

inline std::shared_ptr<Response> Client::get(const char* url)
{
    auto res = std::make_shared<Response>();
    return get(url, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::post(
    const char* url, const std::string& body, const char* content_type)
{
    auto res = std::make_shared<Response>();
    return post(url, body, content_type, *res) ? res : nullptr;
}

} // namespace httplib

#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
