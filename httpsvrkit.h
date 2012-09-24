//
//  httpsvrkit.h
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <functional>
#include <map>
#include <regex>
#include <string>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

typedef SOCKET socket_t;

int inet_aton(const char* strptr, struct in_addr* addrptr)
{
    unsigned long addr = inet_addr(strptr);
    if (addr == ULONG_MAX)
        return 0;
    addrptr->s_addr = addr;
    return 1;
}
#else
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int socket_t;
#endif

namespace httpsvrkit
{

typedef std::map<std::string, std::string>      Map;
typedef std::multimap<std::string, std::string> MultiMap;

// HTTP request
struct Request {
    Map         headers;
    std::string body;
    std::string pattern;
    Map         params;
};

// HTTP response
struct Response {
    MultiMap    headers;
    std::string body;
};

struct Context {
    const Request request;
    Response      response;
};

// HTTP server
class Server {
public:
    typedef std::function<void (Context& context)> Handler;

    Server();
    ~Server();

    void get(const std::string& pattern, Handler handler);
    void post(const std::string& pattern, Handler handler);

    bool run(const std::string& ipaddr, int port);
    void stop();

private:
    void process_request(int fd);

    socket_t sock_;
    std::multimap<std::string, Handler> handlers_;
};

// Implementation

template <typename Fn>
void fdopen_b(int fd, const char* md, Fn fn)
{
#ifdef _WIN32
    int osfhandle = _open_osfhandle(fd, _O_RDONLY);
    FILE* fp = fdopen(osfhandle, md);
#else
    FILE* fp = fdopen(fd, md);
#endif

    if (fp) {
        fn(fp);
        fclose(fp);

#ifdef _WIN32
        close(osfhandle);
#endif
    }
}

inline socket_t create_socket(const std::string& ipaddr, int port)
{
    // Create a server socket
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return -1;
    }

    // Make 'reuse address' option available
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

    // Bind the socket to the given address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_aton(ipaddr.c_str(), &addr.sin_addr) <= 0) {
        return -1;
    }

    if (::bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
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
#endif
}

inline Server::~Server()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

inline void Server::get(const std::string& pattern, Handler handler)
{
    handlers_.insert(std::make_pair(pattern, handler));
}

inline void Server::post(const std::string& pattern, Handler handler)
{
    handlers_.insert(std::make_pair(pattern, handler));
}

inline bool Server::run(const std::string& ipaddr, int port)
{
    sock_ = create_socket(ipaddr, port);
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

        process_request(fd);
        close(fd);
    }

    // NOTREACHED
}

inline void Server::stop()
{
    close_socket(sock_);
    sock_ = -1;
}

inline bool read_request_line(FILE* fp, std::string& method, std::string& url)
{
    static std::regex re("(GET|POST) (.+) HTTP/1\\.1\r\n");

    const size_t BUFSIZ_REQUESTLINE = 2048;
    char buf[BUFSIZ_REQUESTLINE];
    fgets(buf, BUFSIZ_REQUESTLINE, fp);

    std::cmatch m;
    if (std::regex_match(buf, m, re)) {
        method = std::string(m[1]);
        url = std::string(m[2]);
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

inline void write_plain_text(int fd, const char* s)
{
    fdopen_b(fd, "w", [=](FILE* fp) {
        fprintf(fp, "HTTP/1.0 200 OK\r\n");
        fprintf(fp, "Content-type: text/plain\r\n");
        fprintf(fp, "Connection: close\r\n");
        fprintf(fp, "\r\n");
        fprintf(fp, "%s", s);
    });
}

inline void write_error(int fd, int code)
{
    const char* msg = NULL;

    switch (code) {
    case 400:
        msg = "Bad Request";
        break;
    case 404:
        msg = "Not Found";
        break;
    default:
        code = 500;
        msg = "Internal Server Error";
        break;
    }

    assert(msg);

    fdopen_b(fd, "w", [=](FILE* fp) {
        fprintf(fp, "HTTP/1.0 %d %s\r\n", code, msg);
        fprintf(fp, "Content-type: text/plain\r\n");
        fprintf(fp, "Connection: close\r\n");
        fprintf(fp, "\r\n");
        fprintf(fp, "Status: %d\r\n", code);
    });
}

inline void Server::process_request(int fd)
{
    fdopen_b(fd, "r", [=](FILE* fp) {
        // Read and parse request line
        std::string method, url;
        if (!read_request_line(fp, method, url)) {
            write_error(fd, 400);
            return;
        }

        // Read headers
        Map headers;
        read_headers(fp, headers);

        // Write content
        char buf[BUFSIZ];
        std::string content;
        sprintf(buf, "Method: %s, URL: %s\n", method.c_str(), url.c_str());
        content += buf;
        for (const auto& x : headers) {
            sprintf(buf, "%s: %s\n", x.first.c_str(), x.second.c_str());
            content += buf;
        }
        write_plain_text(fd, content.c_str());
    });
}

} // namespace httpsvrkit

// vim: et ts=4 sw=4 cin cino={1s ff=unix

