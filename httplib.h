//
//  httplib.h
//
//  Copyright (c) 2017 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#ifndef _CPPHTTPLIB_HTTPLIB_H_
#define _CPPHTTPLIB_HTTPLIB_H_

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf_s
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m)&S_IFREG)==S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFDIR)==S_IFDIR)
#endif

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
#include <signal.h>
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

#ifdef __has_include
#if __has_include(<openssl/ssl.h>)
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#endif
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#endif

namespace httplib
{

enum class HttpVersion { v1_0 = 0, v1_1 };

typedef std::multimap<std::string, std::string>              MultiMap;
typedef std::smatch                                          Match;
typedef std::function<void (int64_t current, int64_t total)> Progress;

struct MultipartFile {
    std::string filename;
    std::string content_type;
    size_t offset = 0;
    size_t length = 0;
};
typedef std::multimap<std::string, MultipartFile> MultipartFiles;

struct Request {
    std::string    method;
    std::string    path;
    MultiMap       headers;
    std::string    body;
    MultiMap       params;
    MultipartFiles files;
    Match          matches;
    Progress       progress;

    bool has_header(const char* key) const;
    std::string get_header_value(const char* key) const;
    void set_header(const char* key, const char* val);

    bool has_param(const char* key) const;
    std::string get_param_value(const char* key) const;

    bool has_file(const char* key) const;
    MultipartFile get_file_value(const char* key) const;
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

class Stream {
public:
    virtual ~Stream() {}
    virtual int read(char* ptr, size_t size) = 0;
    virtual int write(const char* ptr, size_t size1) = 0;
    virtual int write(const char* ptr) = 0;
};

class SocketStream : public Stream {
public:
    SocketStream(socket_t sock);
    virtual ~SocketStream();

    virtual int read(char* ptr, size_t size);
    virtual int write(const char* ptr, size_t size);
    virtual int write(const char* ptr);

private:
    socket_t sock_;
};

class Server {
public:
    typedef std::function<void (const Request&, Response&)> Handler;
    typedef std::function<void (const Request&, const Response&)> Logger;

    Server();
    virtual ~Server();

    Server& get(const char* pattern, Handler handler);
    Server& post(const char* pattern, Handler handler);

    bool set_base_dir(const char* path);

    void set_error_handler(Handler handler);
    void set_logger(Logger logger);

    bool listen(const char* host, int port, int socket_flags = 0);
    void stop();

protected:
    void process_request(Stream& strm);

private:
    typedef std::vector<std::pair<std::regex, Handler>> Handlers;

    bool routing(Request& req, Response& res);
    bool handle_file_request(Request& req, Response& res);
    bool dispatch_request(Request& req, Response& res, Handlers& handlers);

    bool read_request_line(Stream& strm, Request& req);
    void write_response(Stream& strm, const Request& req, Response& res);

    virtual bool read_and_close_socket(socket_t sock);

    socket_t    svr_sock_;
    std::string base_dir_;
    Handlers    get_handlers_;
    Handlers    post_handlers_;
    Handler     error_handler_;
    Logger      logger_;
};

class Client {
public:
    Client(const char* host, int port, HttpVersion http_version = HttpVersion::v1_0);
    virtual ~Client();

    std::shared_ptr<Response> get(const char* path, Progress callback = [](int64_t,int64_t){});
    std::shared_ptr<Response> head(const char* path);
    std::shared_ptr<Response> post(const char* path, const std::string& body, const char* content_type);
    std::shared_ptr<Response> post(const char* path, const MultiMap& params);

    bool send(const Request& req, Response& res);

protected:
    bool process_request(Stream& strm, const Request& req, Response& res);

    const std::string host_;
    const int         port_;
    const HttpVersion http_version_;
    const std::string host_and_port_;

private:
    bool read_response_line(Stream& strm, Response& res);
    void add_default_headers(Request& req);

    virtual bool read_and_close_socket(socket_t sock, const Request& req, Response& res);
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLSocketStream : public Stream {
public:
    SSLSocketStream(SSL* ssl);
    virtual ~SSLSocketStream();

    virtual int read(char* ptr, size_t size);
    virtual int write(const char* ptr, size_t size);
    virtual int write(const char* ptr);

private:
    SSL* ssl_;
};

class SSLServer : public Server {
public:
    SSLServer(const char* cert_path, const char* private_key_path);
    virtual ~SSLServer();

private:
    virtual bool read_and_close_socket(socket_t sock);

    SSL_CTX* ctx_;
};

class SSLClient : public Client {
public:
    SSLClient(const char* host, int port, HttpVersion http_version = HttpVersion::v1_0);
    virtual ~SSLClient();

private:
    virtual bool read_and_close_socket(socket_t sock, const Request& req, Response& res);

    SSL_CTX* ctx_;
};
#endif

/*
 * Implementation
 */
namespace detail {

static std::vector<const char*> http_version_strings = { "HTTP/1.0", "HTTP/1.1" };

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

class stream_line_reader {
public:
    stream_line_reader(Stream& strm, char* fixed_buffer, size_t fixed_buffer_size)
        : strm_(strm)
        , fixed_buffer_(fixed_buffer)
        , fixed_buffer_size_(fixed_buffer_size) {
    }

    const char* ptr() const {
        if (glowable_buffer_.empty()) {
            return fixed_buffer_;
        } else {
            return glowable_buffer_.data();
        }
    }

    bool getline() {
        fixed_buffer_used_size_ = 0;
        glowable_buffer_.clear();

        size_t i = 0;

        for (;;) {
            char byte;
            auto n = strm_.read(&byte, 1);

            if (n < 1) {
                if (i == 0) {
                    return false;
                } else {
                    break;
                }
            }

            append(byte);

            if (byte == '\n') {
                break;
            }
        }

        append('\0');
        return true;
    }

private:
    void append(char c) {
        if (fixed_buffer_used_size_ < fixed_buffer_size_) {
            fixed_buffer_[fixed_buffer_used_size_++] = c;
        } else {
            if (glowable_buffer_.empty()) {
                glowable_buffer_.assign(fixed_buffer_, fixed_buffer_size_);
            }
            glowable_buffer_ += c;
        }
    }

    Stream& strm_;
    char* fixed_buffer_;
    const size_t fixed_buffer_size_;
    size_t fixed_buffer_used_size_;
    std::string glowable_buffer_;
};

template <typename ...Args>
inline void stream_write_format(Stream& strm, const char* fmt, const Args& ...args)
{
    const auto bufsiz = 2048;
    char buf[bufsiz];

    auto n = snprintf(buf, bufsiz - 1, fmt, args...);
    if (n > 0) {
        if (n >= bufsiz - 1) {
            std::vector<char> glowable_buf(bufsiz);

            while (n >= static_cast<int>(glowable_buf.size() - 1)) {
                glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
                n = _snprintf_s(&glowable_buf[0], glowable_buf.size(), glowable_buf.size() - 1, fmt, args...);
#else
                n = snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...);
#endif
            }
            strm.write(&glowable_buf[0], n);
        } else {
            strm.write(buf, n);
        }
    }
}

inline int close_socket(socket_t sock)
{
#ifdef _WIN32
    return closesocket(sock);
#else
    return close(sock);
#endif
}

template <typename T>
inline bool read_and_close_socket(socket_t sock, T callback)
{
    SocketStream strm(sock);
    auto ret = callback(strm);
    close_socket(sock);
    return ret;
}

inline int shutdown_socket(socket_t sock)
{
#ifdef _WIN32
    return shutdown(sock, SD_BOTH);
#else
    return shutdown(sock, SHUT_RDWR);
#endif
}

template <typename Fn>
socket_t create_socket(const char* host, int port, Fn fn, int socket_flags = 0)
{
#ifdef _WIN32
#define SO_SYNCHRONOUS_NONALERT 0x20
#define SO_OPENTYPE 0x7008

    int opt = SO_SYNCHRONOUS_NONALERT;
    setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char*)&opt, sizeof(opt));
#endif

    // Get address info
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = socket_flags;
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

inline socket_t create_server_socket(const char* host, int port, int socket_flags)
{
    return create_socket(host, port, [](socket_t sock, struct addrinfo& ai) -> socket_t {
        if (::bind(sock, ai.ai_addr, ai.ai_addrlen)) {
              return false;
        }
        if (listen(sock, 5)) { // Listen through 5 channels
            return false;
        }
        return true;
    }, socket_flags);
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

inline bool is_file(const std::string& path)
{
    struct stat st;
    return stat(path.c_str(), &st) >= 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string& path)
{
    struct stat st;
    return stat(path.c_str(), &st) >= 0 && S_ISDIR(st.st_mode);
}

inline bool is_valid_path(const std::string& path) {
    size_t level = 0;
    size_t i = 0;

    // Skip slash
    while (i < path.size() && path[i] == '/') {
        i++;
    }

    while (i < path.size()) {
        // Read component
        auto beg = i;
        while (i < path.size() && path[i] != '/') {
            i++;
        }

        auto len = i - beg;
        assert(len > 0);

        if (!path.compare(beg, len, ".")) {
            ;
        } else if (!path.compare(beg, len, "..")) {
            if (level == 0) {
                return false;
            }
            level--;
        } else {
            level++;
        }

        // Skip slash
        while (i < path.size() && path[i] == '/') {
            i++;
        }
    }

    return true;
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

inline std::string file_extension(const std::string& path)
{
    std::smatch m;
    auto pat = std::regex("\\.([a-zA-Z0-9]+)$");
    if (std::regex_search(path, m, pat)) {
        return m[1].str();
    }
    return std::string();
}

inline const char* content_type(const std::string& path)
{
    auto ext = file_extension(path);
    if (ext == "txt") {
        return "text/plain";
    } else if (ext == "html") {
        return "text/html";
    } else if (ext == "js") {
        return "text/javascript";
    } else if (ext == "css") {
        return "text/css";
    } else if (ext == "xml") {
        return "text/xml";
    } else if (ext == "jpeg" || ext == "jpg") {
        return "image/jpg";
    } else if (ext == "png") {
        return "image/png";
    } else if (ext == "gif") {
        return "image/gif";
    } else if (ext == "svg") {
        return "image/svg+xml";
    } else if (ext == "ico") {
        return "image/x-icon";
    } else if (ext == "json") {
        return "application/json";
    } else if (ext == "pdf") {
        return "application/pdf";
    } else if (ext == "xhtml") {
        return "application/xhtml+xml";
    }
    return nullptr;
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

inline const char* get_header_value(const MultiMap& headers, const char* key, const char* def)
{
    auto it = headers.find(key);
    if (it != headers.end()) {
        return it->second.c_str();
    }
    return def;
}

inline int get_header_value_int(const MultiMap& headers, const char* key, int def)
{
    auto it = headers.find(key);
    if (it != headers.end()) {
        return std::stoi(it->second);
    }
    return def;
}

inline bool read_headers(Stream& strm, MultiMap& headers)
{
    static std::regex re("(.+?): (.+?)\r\n");

    const auto bufsiz = 2048;
    char buf[bufsiz];

    stream_line_reader reader(strm, buf, bufsiz);

    for (;;) {
        if (!reader.getline()) {
            return false;
        }
        if (!strcmp(reader.ptr(), "\r\n")) {
            break;
        }
        std::cmatch m;
        if (std::regex_match(reader.ptr(), m, re)) {
            auto key = std::string(m[1]);
            auto val = std::string(m[2]);
            headers.emplace(key, val);
        }
    }

    return true;
}

template <typename T>
bool read_content_with_length(Stream& strm, T& x, size_t len, Progress progress)
{
    x.body.assign(len, 0);
    size_t r = 0;
    while (r < len){
        auto r_incr = strm.read(&x.body[r], len - r);
        if (r_incr <= 0) {
            return false;
        }
        r += r_incr;
        if (progress) {
            progress(r, len);
        }
    }

    return true;
}

template <typename T>
bool read_content_without_length(Stream& strm, T& x)
{
    for (;;) {
        char byte;
        auto n = strm.read(&byte, 1);
        if (n < 0) {
            return false;
        } else if (n == 0) {
            break;
        }
        x.body += byte;
    }

    return true;
}

template <typename T>
bool read_content_chunked(Stream& strm, T& x)
{
    const auto bufsiz = 16;
    char buf[bufsiz];

    stream_line_reader reader(strm, buf, bufsiz);

    if (!reader.getline()) {
        return false;
    }

    auto chunk_len = std::stoi(reader.ptr(), 0, 16);

    while (chunk_len > 0){
        std::string chunk(chunk_len, 0);

        auto n = strm.read(&chunk[0], chunk_len);
        if (n <= 0) {
            return false;
        }

        if (!reader.getline()) {
            return false;
        }

        if (strcmp(reader.ptr(), "\r\n")) {
            break;
        }

        x.body += chunk;

        if (!reader.getline()) {
            return false;
        }

        chunk_len = std::stoi(reader.ptr(), 0, 16);
    }

    return true;
}

template <typename T>
bool read_content(Stream& strm, T& x, Progress progress = [](int64_t,int64_t){})
{
    auto len = get_header_value_int(x.headers, "Content-Length", 0);

    if (len) {
        return read_content_with_length(strm, x, len, progress);
    } else {
        auto encoding = get_header_value(x.headers, "Transfer-Encoding", "");

        if (!strcmp(encoding, "chunked")) {
            return read_content_chunked(strm, x);
        } else {
            return read_content_without_length(strm, x);
        }
    }

    return true;
}

template <typename T>
inline void write_headers(Stream& strm, const T& info)
{
    strm.write("Connection: close\r\n");

    for (const auto& x: info.headers) {
        if (x.first != "Content-Type" && x.first != "Content-Length") {
            stream_write_format(strm, "%s: %s\r\n", x.first.c_str(), x.second.c_str());
        }
    }

    auto t = get_header_value(info.headers, "Content-Type", "text/plain");
    stream_write_format(strm, "Content-Type: %s\r\n", t);
    stream_write_format(strm, "Content-Length: %ld\r\n", info.body.size());
    strm.write("\r\n");
}

inline void write_response(Stream& strm, const Request& req, const Response& res)
{
    stream_write_format(strm, "HTTP/1.0 %d %s\r\n", res.status, status_message(res.status));

    write_headers(strm, res);

    if (!res.body.empty() && req.method != "HEAD") {
        strm.write(res.body.c_str(), res.body.size());
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
                size_t len = snprintf(hex, sizeof(hex) - 1, "%02X", (unsigned char)s[i]);
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

inline bool from_hex_to_i(const std::string& s, int i, int cnt, int& val)
{
    val = 0;
    for (; cnt; i++, cnt--) {
        if (!s[i]) {
            return false;
        }
        int v = 0;
        if (is_hex(s[i], v)) {
            val = val * 16 + v;
        } else {
            return false;
        }
    }
    return true;
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
            if (s[i + 1] && s[i + 1] == 'u') {
                int val = 0;
                if (from_hex_to_i(s, i + 2, 4, val)) {
                    // 4 digits Unicode codes
                    char buff[4];
                    size_t len = to_utf8(val, buff);
                    if (len > 0) {
                        result.append(buff, len);
                    }
                    i += 5; // 'u0000'
                } else {
                    result += s[i];
                }
            } else {
                int val = 0;
                if (from_hex_to_i(s, i + 1, 2, val)) {
                    // 2 digits hex codes
                    result += val;
                    i += 2; // '00'
                } else {
                    result += s[i];
                }
            }
        } else if (s[i] == '+') {
            result += ' ';
        } else {
            result += s[i];
        }
    }

    return result;
}

inline void write_request(Stream& strm, const Request& req, const char* ver)
{
    auto path = encode_url(req.path);
    stream_write_format(strm, "%s %s %s\r\n", req.method.c_str(), path.c_str(), ver);

    write_headers(strm, req);

    if (!req.body.empty()) {
        if (req.has_header("application/x-www-form-urlencoded")) {
            auto str = encode_url(req.body);
            strm.write(str.c_str(), str.size());
        } else {
            strm.write(req.body.c_str(), req.body.size());
        }
    }
}

inline void parse_query_text(const std::string& s, MultiMap& params)
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
        params.emplace(key, decode_url(val));
    });
}

inline bool parse_multipart_boundary(const std::string& content_type, std::string& boundary)
{
    auto pos = content_type.find("boundary=");
    if (pos == std::string::npos) {
        return false;
    }

    boundary = content_type.substr(pos + 9);
    return true;
}

inline bool parse_multipart_formdata(
    const std::string& boundary, const std::string& body, MultipartFiles& files)
{
    static std::string dash = "--";
    static std::string crlf = "\r\n";

    static std::regex re_content_type(
        "Content-Type: (.*?)");

    static std::regex re_content_disposition(
        "Content-Disposition: form-data; name=\"(.*?)\"(?:; filename=\"(.*?)\")?");

    auto dash_boundary = dash + boundary;

    auto pos = body.find(dash_boundary);
    if (pos != 0) {
        return false;
    }

    pos += dash_boundary.size();

    auto next_pos = body.find(crlf, pos);
    if (next_pos == std::string::npos) {
        return false;
    }

    pos = next_pos + crlf.size();

    while (pos < body.size()) {
        next_pos = body.find(crlf, pos);
        if (next_pos == std::string::npos) {
            return false;
        }

        std::string name;
        MultipartFile file;

        auto header = body.substr(pos, (next_pos - pos));

        while (pos != next_pos) {
            std::smatch m;
            if (std::regex_match(header, m, re_content_type)) {
                file.content_type = m[1];
            } else if (std::regex_match(header, m, re_content_disposition)) {
                name = m[1];
                file.filename = m[2];
            }

            pos = next_pos + crlf.size();

            next_pos = body.find(crlf, pos);
            if (next_pos == std::string::npos) {
                return false;
            }

            header = body.substr(pos, (next_pos - pos));
        }

        pos = next_pos + crlf.size();

        next_pos = body.find(crlf + dash_boundary, pos);

        if (next_pos == std::string::npos) {
            return false;
        }

        file.offset = pos;
        file.length = next_pos - pos;

        pos = next_pos + crlf.size() + dash_boundary.size();

        next_pos = body.find(crlf, pos);
        if (next_pos == std::string::npos) {
            return false;
        }

        files.emplace(name, file);

        pos = next_pos + crlf.size();
    }

    return true;
}

#ifdef _WIN32
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
    headers.emplace(key, val);
}

inline bool Request::has_param(const char* key) const
{
    return params.find(key) != params.end();
}

inline std::string Request::get_param_value(const char* key) const
{
    auto it = params.find(key);
    if (it != params.end()) {
        return it->second;
    }
    return std::string();
}

inline bool Request::has_file(const char* key) const
{
    return files.find(key) != files.end();
}

inline MultipartFile Request::get_file_value(const char* key) const
{
    auto it = files.find(key);
    if (it != files.end()) {
        return it->second;
    }
    return MultipartFile();
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
    headers.emplace(key, val);
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

// Socket stream implementation
inline SocketStream::SocketStream(socket_t sock): sock_(sock)
{
}

inline SocketStream::~SocketStream()
{
}

inline int SocketStream::read(char* ptr, size_t size)
{
    return recv(sock_, ptr, size, 0);
}

inline int SocketStream::write(const char* ptr, size_t size)
{
    return send(sock_, ptr, size, 0);
}

inline int SocketStream::write(const char* ptr)
{
    return write(ptr, strlen(ptr));
}

// HTTP server implementation
inline Server::Server()
    : svr_sock_(-1)
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
}

inline Server::~Server()
{
}

inline Server& Server::get(const char* pattern, Handler handler)
{
    get_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
    return *this;
}

inline Server& Server::post(const char* pattern, Handler handler)
{
    post_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
    return *this;
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

inline bool Server::listen(const char* host, int port, int socket_flags)
{
    svr_sock_ = detail::create_server_socket(host, port, socket_flags);
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
        read_and_close_socket(sock);
    }

    return ret;
}

inline void Server::stop()
{
    detail::shutdown_socket(svr_sock_);
    detail::close_socket(svr_sock_);
    svr_sock_ = -1;
}

inline bool Server::read_request_line(Stream& strm, Request& req)
{
    const auto bufsiz = 2048;
    char buf[bufsiz];

    detail::stream_line_reader reader(strm, buf, bufsiz);

    if (!reader.getline()) {
        return false;
    }

    static std::regex re("(GET|HEAD|POST) ([^?]+)(?:\\?(.+?))? HTTP/1\\.[01]\r\n");

    std::cmatch m;
    if (std::regex_match(reader.ptr(), m, re)) {
        req.method = std::string(m[1]);
        req.path = detail::decode_url(m[2]);

        // Parse query text
        auto len = std::distance(m[3].first, m[3].second);
        if (len > 0) {
            detail::parse_query_text(m[3], req.params);
        }

        return true;
    }

    return false;
}

inline void Server::write_response(Stream& strm, const Request& req, Response& res)
{
    assert(res.status != -1);

    if (400 <= res.status && error_handler_) {
        error_handler_(req, res);
    }

    detail::write_response(strm, req, res);

    if (logger_) {
        logger_(req, res);
    }
}

inline bool Server::handle_file_request(Request& req, Response& res)
{
    if (!base_dir_.empty() && detail::is_valid_path(req.path)) {
        std::string path = base_dir_ + req.path;

        if (!path.empty() && path.back() == '/') {
            path += "index.html";
        }

        if (detail::is_file(path)) {
            detail::read_file(path, res.body);
            auto type = detail::content_type(path);
            if (type) {
                res.set_header("Content-Type", type);
            }
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

        if (std::regex_match(req.path, req.matches, pattern)) {
            handler(req, res);
            return true;
        }
    }
    return false;
}

inline void Server::process_request(Stream& strm)
{
    Request req;
    Response res;

    if (!read_request_line(strm, req) || !detail::read_headers(strm, req.headers)) {
        res.status = 400;
        write_response(strm, req, res);
        return;
    }

    if (req.method == "POST") {
        if (!detail::read_content(strm, req)) {
            res.status = 400;
            write_response(strm, req, res);
            return;
        }

        const auto& content_type = req.get_header_value("Content-Type");

        if (!content_type.find("application/x-www-form-urlencoded")) {
            detail::parse_query_text(req.body, req.params);
        } else if(!content_type.find("multipart/form-data")) {
            std::string boundary;
            if (!detail::parse_multipart_boundary(content_type, boundary) ||
                !detail::parse_multipart_formdata(boundary, req.body, req.files)) {
                res.status = 400;
                write_response(strm, req, res);
                return;
            }
        }
    }

    if (routing(req, res)) {
        if (res.status == -1) {
            res.status = 200;
        }
    } else {
        res.status = 404;
    }

    write_response(strm, req, res);
}

inline bool Server::read_and_close_socket(socket_t sock)
{
    return detail::read_and_close_socket(sock, [this](Stream& strm) {
        process_request(strm);
        return true;
    });
}

// HTTP client implementation
inline Client::Client(const char* host, int port, HttpVersion http_version)
    : host_(host)
    , port_(port)
    , http_version_(http_version)
    , host_and_port_(host_ + ":" + std::to_string(port_))
{
}

inline Client::~Client()
{
}

inline bool Client::read_response_line(Stream& strm, Response& res)
{
    const auto bufsiz = 2048;
    char buf[bufsiz];

    detail::stream_line_reader reader(strm, buf, bufsiz);

    if (!reader.getline()) {
        return false;
    }

    const static std::regex re("HTTP/1\\.[01] (\\d+?) .+\r\n");

    std::cmatch m;
    if (std::regex_match(reader.ptr(), m, re)) {
        res.status = std::stoi(std::string(m[1]));
    }

    return true;
}

inline bool Client::send(const Request& req, Response& res)
{
    if (req.path.empty()) {
        return false;
    }

    auto sock = detail::create_client_socket(host_.c_str(), port_);
    if (sock == -1) {
        return false;
    }

    return read_and_close_socket(sock, req, res);
}

inline bool Client::process_request(Stream& strm, const Request& req, Response& res)
{
    // Send request
    auto ver = detail::http_version_strings[static_cast<size_t>(http_version_)];
    detail::write_request(strm, req, ver);

    // Receive response
    if (!read_response_line(strm, res) ||
        !detail::read_headers(strm, res.headers)) {
        return false;
    }

    if (req.method != "HEAD") {
        if (!detail::read_content(strm, res, req.progress)) {
            return false;
        }
    }

    return true;
}

inline bool Client::read_and_close_socket(socket_t sock, const Request& req, Response& res)
{
    return detail::read_and_close_socket(sock, [&](Stream& strm) {
        return process_request(strm, req, res);
    });
}

inline void Client::add_default_headers(Request& req)
{
    req.set_header("Host", host_and_port_.c_str());
    req.set_header("Accept", "*/*");
    req.set_header("User-Agent", "cpp-httplib/0.1");
}

inline std::shared_ptr<Response> Client::get(const char* path, Progress callback)
{
    Request req;
    req.method = "GET";
    req.path = path;
    req.progress = callback;
    add_default_headers(req);

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::head(const char* path)
{
    Request req;
    req.method = "HEAD";
    req.path = path;
    add_default_headers(req);

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::post(
    const char* path, const std::string& body, const char* content_type)
{
    Request req;
    req.method = "POST";
    req.path = path;
    add_default_headers(req);

    req.set_header("Content-Type", content_type);
    req.body = body;

    auto res = std::make_shared<Response>();

    return send(req, *res) ? res : nullptr;
}

inline std::shared_ptr<Response> Client::post(
    const char* path, const MultiMap& params)
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

    return post(path, query, "application/x-www-form-urlencoded");
}

/*
 * SSL Implementation
 */
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
namespace detail {

template <typename U, typename V, typename T>
inline bool read_and_close_socket_ssl(socket_t sock, SSL_CTX* ctx, U SSL_connect_or_accept, V setup, T callback)
{
    auto ssl = SSL_new(ctx);

    auto bio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    setup(ssl);

    SSL_connect_or_accept(ssl);

    SSLSocketStream strm(ssl);
    auto ret = callback(strm);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close_socket(sock);
    return ret;
}

class SSLInit {
public:
    SSLInit() {
        SSL_load_error_strings();
        SSL_library_init();
    }
};

static SSLInit sslinit_;

} // namespace detail

// SSL socket stream implementation
inline SSLSocketStream::SSLSocketStream(SSL* ssl): ssl_(ssl)
{
}

inline SSLSocketStream::~SSLSocketStream()
{
}

inline int SSLSocketStream::read(char* ptr, size_t size)
{
    return SSL_read(ssl_, ptr, size);
}

inline int SSLSocketStream::write(const char* ptr, size_t size)
{
    return SSL_write(ssl_, ptr, size);
}

inline int SSLSocketStream::write(const char* ptr)
{
    return write(ptr, strlen(ptr));
}

// SSL HTTP server implementation
inline SSLServer::SSLServer(const char* cert_path, const char* private_key_path)
{
    ctx_ = SSL_CTX_new(SSLv23_server_method());

    if (ctx_) {
        SSL_CTX_set_options(ctx_,
                            SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                            SSL_OP_NO_COMPRESSION |
                            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

        // auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        // SSL_CTX_set_tmp_ecdh(ctx_, ecdh);
        // EC_KEY_free(ecdh);

        if (SSL_CTX_use_certificate_file(ctx_, cert_path, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx_, private_key_path, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }
}

inline SSLServer::~SSLServer()
{
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

inline bool SSLServer::read_and_close_socket(socket_t sock)
{
    return detail::read_and_close_socket_ssl(
        sock, ctx_,
        SSL_accept,
        [](SSL* /*ssl*/) {},
        [this](Stream& strm) {
            process_request(strm);
            return true;
        });
}

// SSL HTTP client implementation
inline SSLClient::SSLClient(const char* host, int port, HttpVersion http_version)
    : Client(host, port, http_version)
{
    ctx_ = SSL_CTX_new(SSLv23_client_method());
}

inline SSLClient::~SSLClient()
{
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

inline bool SSLClient::read_and_close_socket(socket_t sock, const Request& req, Response& res)
{
    return detail::read_and_close_socket_ssl(
        sock, ctx_,
        SSL_connect,
        [&](SSL* ssl) {
            SSL_set_tlsext_host_name(ssl, host_.c_str());
        },
        [&](Stream& strm) {
            return process_request(strm, req, res);
        });
}
#endif

} // namespace httplib

#endif

// vim: et ts=4 sw=4 cin cino={1s ff=unix
