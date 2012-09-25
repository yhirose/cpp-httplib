//
//  httpsvrkit.h
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#ifdef _WIN32
//#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

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

namespace httpsvrkit
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
    MultiMap    headers;
    std::string body;
};

struct Context {
    Request  request;
    Response response;
};

// HTTP server
class Server {
public:
    typedef std::function<int (Context& context)> Handler;

    Server();
    ~Server();

    void get(const char* pattern, Handler handler);
    void post(const char* pattern, Handler handler);

    bool run(const char* ipaddr_or_hostname, int port);
    void stop();

private:
    void process_request(FILE* fp_read, FILE* fp_write);

    socket_t sock_;
    std::vector<std::pair<std::regex, Handler>> get_handlers_;
    std::vector<std::pair<std::string, Handler>> post_handlers_;
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

inline socket_t create_server_socket(const const char* ipaddr_or_hostname, int port)
{
    // Create a server socket
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return -1;
    }

    // Make 'reuse address' option available
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

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
        puts("(error)\n");
        return -1;
    }

    // Listen through 5 channels
    if (listen(sock, 5) != 0) {
        return -1;
    }

    return sock;
}

inline void close_socket(socket_t sock)
{
#ifdef _WIN32
    closesocket(sock);
#else
    shutdown(sock, SHUT_RDWR);
    close(sock);
#endif
}

inline Server::Server()
    : sock_(-1)
{
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(0x0002, &wsaData);

#ifndef SO_SYNCHRONOUS_NONALERT
#define SO_SYNCHRONOUS_NONALERT 0x20;
#endif
#ifndef SO_OPENTYPE
#define SO_OPENTYPE 0x7008
#endif
    int opt = SO_SYNCHRONOUS_NONALERT;
    setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char*)&opt, sizeof(opt));
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

inline bool Server::run(const const char*ipaddr_or_hostname, int port)
{
    sock_ = create_server_socket(ipaddr_or_hostname, port);
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

#ifdef _WIN32
        int osfhandle = _open_osfhandle(fd, _O_RDONLY);
        FILE* fp_read = fdopen(osfhandle, "r");
        FILE* fp_write = fdopen(osfhandle, "w");
#else
        FILE* fp_read = fdopen(fd, "r");
        FILE* fp_write = fdopen(fd, "w");
#endif

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

inline void write_plain_text(FILE* fp, const char* s)
{
    fprintf(fp, "HTTP/1.0 200 OK\r\n");
    fprintf(fp, "Content-type: text/plain\r\n");
    fprintf(fp, "Connection: close\r\n");
    fprintf(fp, "\r\n");
    fprintf(fp, "%s", s);
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
    Context cxt;

    // Read and parse request line
    if (!read_request_line(fp_read, cxt.request)) {
        write_error(fp_write, 400);
        return;
    }

    // Read headers
    read_headers(fp_read, cxt.request.headers);

    // Routing
    int status = 404;

    if (cxt.request.method == "GET") {
        for (auto it = get_handlers_.begin(); it != get_handlers_.end(); ++it) {
            const auto& pattern = it->first;
            const auto& handler = it->second;
            
            std::smatch m;
            if (std::regex_match(cxt.request.url, m, pattern)) {
                for (size_t i = 1; i < m.size(); i++) {
                    cxt.request.params.push_back(m[i]);
                }
                status = handler(cxt);
            }
        }
    } else if (cxt.request.method == "POST") {
        // TODO: parse body
    } else {
        status = 400;
    }

    if (status == 200) {
        write_plain_text(fp_write, cxt.response.body.c_str());
    } else {
        write_error(fp_write, status);
    }
}

} // namespace httpsvrkit

// vim: et ts=4 sw=4 cin cino={1s ff=unix
