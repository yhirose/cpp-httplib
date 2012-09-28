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
#define snprintf sprintf_s
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
typedef std::vector<std::string>                Array;
typedef std::multimap<std::string, std::string> MultiMap;

// HTTP request
struct Request {
    std::string method;
    std::string url;
    Map         headers;
    std::string body;
    Map         query;
    Array       params;
};

// HTTP response
struct Response {
    int         status;
    MultiMap    headers;
    std::string body;

    void set_redirect(const char* url);
    void set_content(const std::string& s, const char* content_type = "text/plain");
};

struct Connection {
    Request  request;
    Response response;
};

// HTTP server
class Server {
public:
    typedef std::function<void (Connection& c)> Handler;

    Server(const char* ipaddr_or_hostname, int port);
    ~Server();

    void get(const char* pattern, Handler handler);
    void post(const char* pattern, Handler handler);

    void on_ready(std::function<void ()> callback);

    bool run();
    void stop();

private:
    void process_request(FILE* fp_read, FILE* fp_write);

    const std::string ipaddr_or_hostname_;
    const int         port_;
    socket_t          sock_;

    std::vector<std::pair<std::regex, Handler>>  get_handlers_;
    std::vector<std::pair<std::string, Handler>> post_handlers_;
    std::function<void ()>                       on_ready_;
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

    if (i != 0) {
        fn(&b[beg], &b[i]);
    }
}

inline socket_t create_server_socket(const char* ipaddr_or_hostname, int port)
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
    if (!(hp = gethostbyname(ipaddr_or_hostname))) {
        return -1;
    }

    // Bind the socket to the given address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (::bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return -1;
    }

    // Listen through 5 channels
    if (listen(sock, 5) != 0) {
        return -1;
    }

    return sock;
}

inline int close_server_socket(socket_t sock)
{
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
    return closesocket(sock);
#else
    shutdown(sock, SHUT_RDWR);
    return close(sock);
#endif
}

std::string dump_request(Connection& c)
{
    const auto& req = c.request;
    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s", req.method.c_str(), req.url.c_str());
    s += buf;

    std::string query;
    for (auto it = req.query.begin(); it != req.query.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%c%s=%s", (it == req.query.begin()) ? '?' : '&', x.first.c_str(), x.second.c_str());
       query += buf;
    }
    snprintf(buf, sizeof(buf), "%s\n", query.c_str());
    s += buf;

    for (auto it = req.headers.begin(); it != req.headers.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
       s += buf;
    }

    return s;
}

void Response::set_redirect(const char* url)
{
    headers.insert(std::make_pair("Location", url));
    status = 302;
}

void Response::set_content(const std::string& s, const char* content_type)
{
    body = s;
    headers.insert(std::make_pair("Content-Type", content_type));
    status = 200;
}

inline Server::Server(const char* ipaddr_or_hostname, int port)
    : ipaddr_or_hostname_(ipaddr_or_hostname)
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

inline void Server::on_ready(std::function<void ()> callback)
{
    on_ready_ = callback;
}

inline bool Server::run()
{
    sock_ = create_server_socket(ipaddr_or_hostname_.c_str(), port_);
    if (sock_ == -1) {
        return false;
    }
    
    if (on_ready_) {
        on_ready_();
    }

    for (;;) {
        socket_t fd = accept(sock_, NULL, NULL);
        if (fd == -1) {
            // The server socket was closed by user.
            if (sock_ == -1) {
                return true;
            } 

            close_server_socket(sock_);
            return false;
        }

#ifdef _WIN32
        int osfhandle = _open_osfhandle(fd, _O_RDONLY);
        FILE* fp_read = fdopen(osfhandle, "rb");
        FILE* fp_write = fdopen(osfhandle, "wb");
#else
        FILE* fp_read = fdopen(fd, "rb");
        FILE* fp_write = fdopen(fd, "wb");
#endif

        process_request(fp_read, fp_write);

        fflush(fp_write);
        close_server_socket(fd);
    }

    // NOTREACHED
}

inline void Server::stop()
{
    close_server_socket(sock_);
    sock_ = -1;
}

inline bool read_request_line(FILE* fp, Request& request)
{
    static std::regex re("(GET|POST) ([^?]+)(?:\\?(.+?))? HTTP/1\\.1\r\n");

    const size_t BUFSIZ_REQUESTLINE = 2048;
    char buf[BUFSIZ_REQUESTLINE];
    fgets(buf, BUFSIZ_REQUESTLINE, fp);

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        request.method = std::string(m[1]);
        request.url = std::string(m[2]);

        // Parse query text
        auto len = std::distance(m[3].first, m[3].second);
        if (len > 0) {
            const auto& pos = m[3];
            split(pos.first, pos.second, '&', [&](const char* b, const char* e) {
                std::string key;
                std::string val;
                split(b, e, '=', [&](const char* b, const char* e) {
                    if (key.empty()) {
                        key.assign(b, e);
                    } else {
                        val.assign(b, e);
                    }
                });
                request.query[key] = val;
            });
        }

        return true;
    }

    return false;
}

inline void read_headers(FILE* fp, Map& headers)
{
    static std::regex re("(.+?): (.+?)\r\n");

    const size_t BUFSIZ_HEADER = 2048;
    char buf[BUFSIZ_HEADER];

    while (fgets(buf, BUFSIZ_HEADER, fp) && strcmp(buf, "\r\n")) {
        std::cmatch m;
        if (std::regex_match(buf, m, re)) {
            auto key = std::string(m[1]);
            auto val = std::string(m[2]);
            headers[key] = val;
        }
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

inline void write_response(FILE* fp, const Response& response)
{
    fprintf(fp, "HTTP/1.0 %d OK\r\n", response.status);
    fprintf(fp, "Connection: close\r\n");

    for (auto it = response.headers.begin(); it != response.headers.end(); ++it) {
        if (it->first != "Content-Type" && it->second != "Content-Length") {
            fprintf(fp, "%s: %s\r\n", it->first.c_str(), it->second.c_str());
        }
    }

    if (!response.body.empty()) {
        auto content_type = get_header_value(response.headers, "Content-Type", "text/plain");
        fprintf(fp, "Content-Type: %s\r\n", content_type);
        fprintf(fp, "Content-Length: %ld\r\n", response.body.size());
    }

    fprintf(fp, "\r\n");

    if (!response.body.empty()) {
        fprintf(fp, "%s", response.body.c_str());
    }
}

inline void write_error(FILE* fp, int status)
{
    const char* msg = NULL;

    switch (status) {
    case 400:
        msg = "Bad Request";
        break;
    case 404:
        msg = "Not Found";
        break;
    default:
        status = 500;
        msg = "Internal Server Error";
        break;
    }

    assert(msg);

    fprintf(fp, "HTTP/1.0 %d %s\r\n", status, msg);
    fprintf(fp, "Content-type: text/plain\r\n");
    fprintf(fp, "Connection: close\r\n");
    fprintf(fp, "\r\n");
    fprintf(fp, "Status: %d\r\n", status);
}

inline void Server::process_request(FILE* fp_read, FILE* fp_write)
{
    Connection c;

    // Read and parse request line
    if (!read_request_line(fp_read, c.request)) {
        write_error(fp_write, 400);
        return;
    }

    // Read headers
    read_headers(fp_read, c.request.headers);
    
    printf("%s", dump_request(c).c_str());

    // Routing
    c.response.status = 404;

    if (c.request.method == "GET") {
        for (auto it = get_handlers_.begin(); it != get_handlers_.end(); ++it) {
            const auto& pattern = it->first;
            const auto& handler = it->second;
            
            std::smatch m;
            if (std::regex_match(c.request.url, m, pattern)) {
                for (size_t i = 1; i < m.size(); i++) {
                    c.request.params.push_back(m[i]);
                }
                handler(c);
                break;
            }
        }
    } else if (c.request.method == "POST") {
        // TODO: parse body
    } else {
        c.response.status = 400;
    }

    if (200 <= c.response.status && c.response.status < 400) {
        write_response(fp_write, c.response);
    } else {
        write_error(fp_write, c.response.status);
    }
}

} // namespace httplib

#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
