#pragma once
#include "configuration.h"
#include "httplib_typedefs.h"
#include "iocp_types.h"
#include "Stream.h"
#include "SocketStream.h"
#include "IOCPStream.h"
#include "stream_line_reader.h"
#include <string>
#include <assert.h>
#include <fstream>
#include <regex>

#ifdef _WIN32
#include <WS2tcpip.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#define INVALID_SOCKET (-1)
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
#include <zlib.h>
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m)&S_IFREG)==S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m)&S_IFDIR)==S_IFDIR)
#endif


namespace httplib
{

	namespace detail
	{

		struct ci {
			bool operator() (const std::string & s1, const std::string & s2) const
			{
				return std::lexicographical_compare(
					s1.begin(), s1.end(),
					s2.begin(), s2.end(),
					[](char c1, char c2) {
						return ::tolower(c1) < ::tolower(c2);
					});
			}
		};

		bool read_headers(Stream& strm, Headers& headers);
		template <typename T>
		bool read_content(Stream& strm, T& x, Progress progress = Progress());
		void parse_query_text(const std::string& s, Params& params);
		bool parse_multipart_boundary(const std::string& content_type, std::string& boundary);
		bool parse_multipart_formdata(const std::string& boundary,
			const std::string& body, MultipartFiles& files);
		std::string get_remote_addr(socket_t sock);
		template <class Fn>
		void split(const char* b, const char* e, char d, Fn fn);
		int close_socket(socket_t sock);
		inline int select_read(socket_t sock, time_t sec, time_t usec);
		inline bool wait_until_socket_is_ready(socket_t sock, time_t sec, time_t usec);
		template <typename T>
		inline bool read_and_close_socket(socket_t sock, size_t keep_alive_max_count, T callback);
		inline int shutdown_socket(socket_t sock);
		template <typename Fn>
		socket_t create_socket(const char* host, int port, Fn fn, int socket_flags = 0);
		inline void set_nonblocking(socket_t sock, bool nonblocking);
		inline bool is_connection_error(void);
		inline std::string get_remote_addr(socket_t sock);
		inline bool is_file(const std::string& path);
		inline bool is_dir(const std::string& path);
		inline bool is_valid_path(const std::string& path);
		inline void read_file(const std::string& path, std::string& out);
		inline std::string file_extension(const std::string& path);
		inline const char* find_content_type(const std::string& path);
		inline const char* status_message(int status);
		inline const char* get_header_value(const Headers& headers, const char* key, const char* def);
		inline int get_header_value_int(const Headers& headers, const char* key, int def);
		inline bool read_headers(Stream& strm, Headers& headers);
		inline bool read_content_with_length(Stream& strm, std::string& out, size_t len, Progress progress);
		inline bool read_content_without_length(Stream& strm, std::string& out);
		inline bool read_content_chunked(Stream& strm, std::string& out);
		template <typename T>
		bool read_content(Stream& strm, T& x, Progress progress);
		template <typename T>
		inline void write_headers(Stream& strm, const T& info);
		inline std::string encode_url(const std::string& s);
		inline bool is_hex(char c, int& v);
		inline bool from_hex_to_i(const std::string& s, size_t i, size_t cnt, int& val);		
		inline std::string from_i_to_hex(uint64_t n);		
		inline size_t to_utf8(int code, char* buff);		
		inline std::string decode_url(const std::string& s);		
		inline void parse_query_text(const std::string& s, Params& params);
		inline bool parse_multipart_boundary(const std::string& content_type, std::string& boundary);		
		inline bool parse_multipart_formdata(const std::string& boundary,
			const std::string& body, MultipartFiles& files);
		inline std::string to_lower(const char* beg, const char* end);
		inline void make_range_header_core(std::string&);
		template<typename uint64_t>
		inline void make_range_header_core(std::string& field, uint64_t value);
		template<typename uint64_t, typename... Args>
		inline void make_range_header_core(std::string& field, uint64_t value1, uint64_t value2, Args... args);

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		inline bool can_compress(const std::string& content_type);
		inline void compress(std::string& content);
		inline void decompress(std::string& content);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		template <typename U, typename V, typename T>
		inline bool read_and_close_socket_ssl(socket_t sock, size_t keep_alive_max_count,
			// TODO: OpenSSL 1.0.2 occasionally crashes...
			// The upcoming 1.1.0 is going to be thread safe.
			SSL_CTX* ctx, std::mutex& ctx_mutex,
			U SSL_connect_or_accept, V setup,
			T callback);

		class SSLInit {
		public:
			SSLInit() {
				SSL_load_error_strings();
				SSL_library_init();
			}
		};

		static SSLInit sslinit_;
#endif

		template<typename uint64_t, typename... Args>
		inline std::pair<std::string, std::string> make_range_header(uint64_t value, Args... args);

#ifdef CPPHTTPLIB_IOCP_SUPPORT
		SOCKET CreateSocket(void);
		template <typename T>
		inline bool read_and_close_iocp_socket(PPER_SOCKET_CONTEXT _lpPerSocketContext,
			PPER_IO_CONTEXT _lpIOContext, DWORD& _dwSendNumBytes, DWORD& _dwFlags,
			size_t keep_alive_max_count, T callback);
#endif

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

		inline int close_socket(socket_t sock)
		{

#ifdef _WIN32
			return closesocket(sock);
#else
			return close(sock);
#endif

		}

		inline int select_read(socket_t sock, time_t sec, time_t usec)
		{
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(sock, &fds);

			timeval tv;
			tv.tv_sec = sec;
			tv.tv_usec = usec;

			return select(sock + 1, &fds, NULL, NULL, &tv);
		}

		inline bool wait_until_socket_is_ready(socket_t sock, time_t sec, time_t usec)
		{
			fd_set fdsr;
			FD_ZERO(&fdsr);
			FD_SET(sock, &fdsr);

			auto fdsw = fdsr;
			auto fdse = fdsr;

			timeval tv;
			tv.tv_sec = sec;
			tv.tv_usec = usec;

			if (select(sock + 1, &fdsr, &fdsw, &fdse, &tv) < 0) {
				return false;
			}
			else if (FD_ISSET(sock, &fdsr) || FD_ISSET(sock, &fdsw)) {
				int error = 0;
				socklen_t len = sizeof(error);
				if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) < 0 || error) {
					return false;
				}
			}
			else {
				return false;
			}

			return true;
		}


		template <typename T>
		inline bool read_and_close_socket(socket_t sock, size_t keep_alive_max_count, T callback)
		{
			bool ret = false;

			if (keep_alive_max_count > 0) {
				auto count = keep_alive_max_count;
				while (count > 0 &&
					detail::select_read(sock,
						CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND,
						CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND) > 0) {
					SocketStream strm(sock);
					auto last_connection = count == 1;
					auto connection_close = false;

					ret = callback(strm, last_connection, connection_close);
					if (!ret || connection_close) {
						break;
					}

					count--;
				}
			}
			else {
				SocketStream strm(sock);
				auto dummy_connection_close = false;
				ret = callback(strm, true, dummy_connection_close);
			}

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
		socket_t create_socket(const char* host, int port, Fn fn, int socket_flags)
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
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = socket_flags;
			hints.ai_protocol = 0;

			auto service = std::to_string(port);

			if (getaddrinfo(host, service.c_str(), &hints, &result)) {
				return INVALID_SOCKET;
			}

			for (auto rp = result; rp; rp = rp->ai_next) {
				// Create a socket
				auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
				if (sock == INVALID_SOCKET) {
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
			return INVALID_SOCKET;
		}

		inline void set_nonblocking(socket_t sock, bool nonblocking)
		{

#ifdef _WIN32
			auto flags = nonblocking ? 1UL : 0UL;
			ioctlsocket(sock, FIONBIO, &flags);
#else
			auto flags = fcntl(sock, F_GETFL, 0);
			fcntl(sock, F_SETFL, nonblocking ? (flags | O_NONBLOCK) : (flags & (~O_NONBLOCK)));
#endif

		}

		inline bool is_connection_error()
		{

#ifdef _WIN32
			return WSAGetLastError() != WSAEWOULDBLOCK;
#else
			return errno != EINPROGRESS;
#endif

		}

		inline std::string get_remote_addr(socket_t sock)
		{
			struct sockaddr_storage addr;
			socklen_t len = sizeof(addr);

			if (!getpeername(sock, (struct sockaddr*)&addr, &len)) {
				char ipstr[NI_MAXHOST];

				if (!getnameinfo((struct sockaddr*)&addr, len,
					ipstr, sizeof(ipstr), nullptr, 0, NI_NUMERICHOST)) {
					return ipstr;
				}
			}

			return std::string();
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
				}
				else if (!path.compare(beg, len, "..")) {
					if (level == 0) {
						return false;
					}
					level--;
				}
				else {
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

		inline const char* find_content_type(const std::string& path)
		{
			auto ext = file_extension(path);
			if (ext == "txt") {
				return "text/plain";
			}
			else if (ext == "html") {
				return "text/html";
			}
			else if (ext == "css") {
				return "text/css";
			}
			else if (ext == "jpeg" || ext == "jpg") {
				return "image/jpg";
			}
			else if (ext == "png") {
				return "image/png";
			}
			else if (ext == "gif") {
				return "image/gif";
			}
			else if (ext == "svg") {
				return "image/svg+xml";
			}
			else if (ext == "ico") {
				return "image/x-icon";
			}
			else if (ext == "json") {
				return "application/json";
			}
			else if (ext == "pdf") {
				return "application/pdf";
			}
			else if (ext == "js") {
				return "application/javascript";
			}
			else if (ext == "xml") {
				return "application/xml";
			}
			else if (ext == "xhtml") {
				return "application/xhtml+xml";
			}
			return nullptr;
		}

		inline const char* status_message(int status)
		{
			switch (status) {
			case 200: return "OK";
			case 301: return "Moved Permanently";
			case 302: return "Found";
			case 303: return "See Other";
			case 304: return "Not Modified";
			case 400: return "Bad Request";
			case 403: return "Forbidden";
			case 404: return "Not Found";
			case 415: return "Unsupported Media Type";
			default:
			case 500: return "Internal Server Error";
			}
		}

		inline const char* get_header_value(const Headers& headers, const char* key, const char* def)
		{
			auto it = headers.find(key);
			if (it != headers.end()) {
				return it->second.c_str();
			}
			return def;
		}

		inline int get_header_value_int(const Headers& headers, const char* key, int def)
		{
			auto it = headers.find(key);
			if (it != headers.end()) {
				return std::stoi(it->second);
			}
			return def;
		}

		inline bool read_headers(Stream& strm, Headers& headers)
		{
			static std::regex re(R"((.+?):\s*(.+?)\s*\r\n)");

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

		inline bool read_content_with_length(Stream& strm, std::string& out, size_t len, Progress progress)
		{
			out.assign(len, 0);
			size_t r = 0;
			while (r < len) {
				auto n = strm.read(&out[r], len - r);
				if (n <= 0) {
					return false;
				}

				r += n;

				if (progress) {
					if (!progress(r, len)) {
						return false;
					}
				}
			}

			return true;
		}

		inline bool read_content_without_length(Stream& strm, std::string& out)
		{
			for (;;) {
				char byte;
				auto n = strm.read(&byte, 1);
				if (n < 0) {
					return false;
				}
				else if (n == 0) {
					return true;
				}
				out += byte;
			}

			return true;
		}

		inline bool read_content_chunked(Stream& strm, std::string& out)
		{
			const auto bufsiz = 16;
			char buf[bufsiz];

			stream_line_reader reader(strm, buf, bufsiz);

			if (!reader.getline()) {
				return false;
			}

			auto chunk_len = std::stoi(reader.ptr(), 0, 16);

			while (chunk_len > 0) {
				std::string chunk;
				if (!read_content_with_length(strm, chunk, chunk_len, nullptr)) {
					return false;
				}

				if (!reader.getline()) {
					return false;
				}

				if (strcmp(reader.ptr(), "\r\n")) {
					break;
				}

				out += chunk;

				if (!reader.getline()) {
					return false;
				}

				chunk_len = std::stoi(reader.ptr(), 0, 16);
			}

			if (chunk_len == 0) {
				// Reader terminator after chunks
				if (!reader.getline() || strcmp(reader.ptr(), "\r\n"))
					return false;
			}

			return true;
		}

		template <typename T>
		bool read_content(Stream& strm, T& x, Progress progress)
		{
			auto len = get_header_value_int(x.headers, "Content-Length", 0);

			if (len) {
				return read_content_with_length(strm, x.body, len, progress);
			}
			else {
				const auto& encoding = get_header_value(x.headers, "Transfer-Encoding", "");

				if (!strcasecmp(encoding, "chunked")) {
					return read_content_chunked(strm, x.body);
				}
				else {
					return read_content_without_length(strm, x.body);
				}
			}

			return true;
		}

		template <typename T>
		inline void write_headers(Stream& strm, const T& info)
		{
			for (const auto& x : info.headers) {
				strm.write_format("%s: %s\r\n", x.first.c_str(), x.second.c_str());
			}
			strm.write("\r\n");
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
					}
					else {
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
			}
			else if ('A' <= c && c <= 'F') {
				v = c - 'A' + 10;
				return true;
			}
			else if ('a' <= c && c <= 'f') {
				v = c - 'a' + 10;
				return true;
			}
			return false;
		}

		inline bool from_hex_to_i(const std::string& s, size_t i, size_t cnt, int& val)
		{
			if (i >= s.size()) {
				return false;
			}

			val = 0;
			for (; cnt; i++, cnt--) {
				if (!s[i]) {
					return false;
				}
				int v = 0;
				if (is_hex(s[i], v)) {
					val = val * 16 + v;
				}
				else {
					return false;
				}
			}
			return true;
		}

		inline std::string from_i_to_hex(uint64_t n)
		{
			const char *charset = "0123456789abcdef";
			std::string ret;
			do {
				ret = charset[n & 15] + ret;
				n >>= 4;
			} while (n > 0);
			return ret;
		}

		inline size_t to_utf8(int code, char* buff)
		{
			if (code < 0x0080) {
				buff[0] = (code & 0x7F);
				return 1;
			}
			else if (code < 0x0800) {
				buff[0] = (0xC0 | ((code >> 6) & 0x1F));
				buff[1] = (0x80 | (code & 0x3F));
				return 2;
			}
			else if (code < 0xD800) {
				buff[0] = (0xE0 | ((code >> 12) & 0xF));
				buff[1] = (0x80 | ((code >> 6) & 0x3F));
				buff[2] = (0x80 | (code & 0x3F));
				return 3;
			}
			else if (code < 0xE000) { // D800 - DFFF is invalid...
				return 0;
			}
			else if (code < 0x10000) {
				buff[0] = (0xE0 | ((code >> 12) & 0xF));
				buff[1] = (0x80 | ((code >> 6) & 0x3F));
				buff[2] = (0x80 | (code & 0x3F));
				return 3;
			}
			else if (code < 0x110000) {
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

			for (size_t i = 0; i < s.size(); i++) {
				if (s[i] == '%' && i + 1 < s.size()) {
					if (s[i + 1] == 'u') {
						int val = 0;
						if (from_hex_to_i(s, i + 2, 4, val)) {
							// 4 digits Unicode codes
							char buff[4];
							size_t len = to_utf8(val, buff);
							if (len > 0) {
								result.append(buff, len);
							}
							i += 5; // 'u0000'
						}
						else {
							result += s[i];
						}
					}
					else {
						int val = 0;
						if (from_hex_to_i(s, i + 1, 2, val)) {
							// 2 digits hex codes
							result += val;
							i += 2; // '00'
						}
						else {
							result += s[i];
						}
					}
				}
				else if (s[i] == '+') {
					result += ' ';
				}
				else {
					result += s[i];
				}
			}

			return result;
		}

		inline void parse_query_text(const std::string& s, Params& params)
		{
			split(&s[0], &s[s.size()], '&', [&](const char* b, const char* e) {
				std::string key;
				std::string val;
				split(b, e, '=', [&](const char* b, const char* e) {
					if (key.empty()) {
						key.assign(b, e);
					}
					else {
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
				"Content-Type: (.*?)", std::regex_constants::icase);

			static std::regex re_content_disposition(
				"Content-Disposition: form-data; name=\"(.*?)\"(?:; filename=\"(.*?)\")?",
				std::regex_constants::icase);

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
					}
					else if (std::regex_match(header, m, re_content_disposition)) {
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

		inline std::string to_lower(const char* beg, const char* end)
		{
			std::string out;
			auto it = beg;
			while (it != end) {
				out += ::tolower(*it);
				it++;
			}
			return out;
		}

		inline void make_range_header_core(std::string&) {}

		template<typename uint64_t>
		inline void make_range_header_core(std::string& field, uint64_t value)
		{
			if (!field.empty()) {
				field += ", ";
			}
			field += std::to_string(value) + "-";
		}

		template<typename uint64_t, typename... Args>
		inline void make_range_header_core(std::string& field, uint64_t value1, uint64_t value2, Args... args)
		{
			if (!field.empty()) {
				field += ", ";
			}
			field += std::to_string(value1) + "-" + std::to_string(value2);
			make_range_header_core(field, args...);
		}

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
		inline bool can_compress(const std::string& content_type) {
			return !content_type.find("text/") ||
				content_type == "image/svg+xml" ||
				content_type == "application/javascript" ||
				content_type == "application/json" ||
				content_type == "application/xml" ||
				content_type == "application/xhtml+xml";
		}

		inline void compress(std::string& content)
		{
			z_stream strm;
			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;

			auto ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
			if (ret != Z_OK) {
				return;
			}

			strm.avail_in = content.size();
			strm.next_in = (Bytef *)content.data();

			std::string compressed;

			const auto bufsiz = 16384;
			char buff[bufsiz];
			do {
				strm.avail_out = bufsiz;
				strm.next_out = (Bytef *)buff;
				deflate(&strm, Z_FINISH);
				compressed.append(buff, bufsiz - strm.avail_out);
			} while (strm.avail_out == 0);

			content.swap(compressed);

			deflateEnd(&strm);
		}

		inline void decompress(std::string& content)
		{
			z_stream strm;
			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;

			// 15 is the value of wbits, which should be at the maximum possible value to ensure
			// that any gzip stream can be decoded. The offset of 16 specifies that the stream
			// to decompress will be formatted with a gzip wrapper.
			auto ret = inflateInit2(&strm, 16 + 15);
			if (ret != Z_OK) {
				return;
			}

			strm.avail_in = content.size();
			strm.next_in = (Bytef *)content.data();

			std::string decompressed;

			const auto bufsiz = 16384;
			char buff[bufsiz];
			do {
				strm.avail_out = bufsiz;
				strm.next_out = (Bytef *)buff;
				inflate(&strm, Z_NO_FLUSH);
				decompressed.append(buff, bufsiz - strm.avail_out);
			} while (strm.avail_out == 0);

			content.swap(decompressed);

			inflateEnd(&strm);
		}
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		template <typename U, typename V, typename T>
		inline bool read_and_close_socket_ssl(
			socket_t sock, size_t keep_alive_max_count,
			// TODO: OpenSSL 1.0.2 occasionally crashes...
			// The upcoming 1.1.0 is going to be thread safe.
			SSL_CTX* ctx, std::mutex& ctx_mutex,
			U SSL_connect_or_accept, V setup,
			T callback)
		{
			SSL* ssl = nullptr;
			{
				std::lock_guard<std::mutex> guard(ctx_mutex);

				ssl = SSL_new(ctx);
				if (!ssl) {
					return false;
				}
			}

			auto bio = BIO_new_socket(sock, BIO_NOCLOSE);
			SSL_set_bio(ssl, bio, bio);

			setup(ssl);

			SSL_connect_or_accept(ssl);

			bool ret = false;

			if (keep_alive_max_count > 0) {
				auto count = keep_alive_max_count;
				while (count > 0 &&
					detail::select_read(sock,
						CPPHTTPLIB_KEEPALIVE_TIMEOUT_SECOND,
						CPPHTTPLIB_KEEPALIVE_TIMEOUT_USECOND) > 0) {
					SSLSocketStream strm(sock, ssl);
					auto last_connection = count == 1;
					auto connection_close = false;

					ret = callback(strm, last_connection, connection_close);
					if (!ret || connection_close) {
						break;
					}

					count--;
				}
			}
			else {
				SSLSocketStream strm(sock, ssl);
				auto dummy_connection_close = false;
				ret = callback(strm, true, dummy_connection_close);
			}

			SSL_shutdown(ssl);

			{
				std::lock_guard<std::mutex> guard(ctx_mutex);
				SSL_free(ssl);
			}

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
#endif

		template<typename uint64_t, typename... Args>
		inline std::pair<std::string, std::string> make_range_header(uint64_t value, Args... args)
		{
			std::string field;
			detail::make_range_header_core(field, value, args...);
			field.insert(0, "bytes=");
			return std::make_pair("Range", field);
		}

#ifdef CPPHTTPLIB_IOCP_SUPPORT
		SOCKET CreateSocket(void) {
			int nRet = 0;
			int nZero = 0;
			SOCKET sdSocket = INVALID_SOCKET;

			sdSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
			if (sdSocket == INVALID_SOCKET) {
				return(sdSocket);
			}

			//
			// Disable send buffering on the socket.  Setting SO_SNDBUF
			// to 0 causes winsock to stop buffering sends and perform
			// sends directly from our buffers, thereby save one memory copy.
			//
			// However, this does prevent the socket from ever filling the
			// send pipeline. This can lead to packets being sent that are
			// not full (i.e. the overhead of the IP and TCP headers is 
			// great compared to the amount of data being carried).
			//
			// Disabling the send buffer has less serious repercussions 
			// than disabling the receive buffer.
			//
			nZero = 0;
			nRet = setsockopt(sdSocket, SOL_SOCKET, SO_SNDBUF, (char *)&nZero, sizeof(nZero));
			if (nRet == SOCKET_ERROR) {
				return(sdSocket);
			}

			// 
			// Do not set a linger value...especially don't set it to an abortive
			// close. If you set abortive close and there happens to be a bit of
			// data remaining to be transfered (or data that has not been 
			// acknowledged by the peer), the connection will be forcefully reset
			// and will lead to a loss of data (i.e. the peer won't get the last
			// bit of data). This is BAD. If you are worried about malicious
			// clients connecting and then not sending or receiving, the server
			// should maintain a timer on each connection. If after some point,
			// the server deems a connection is "stale" it can then set linger
			// to be abortive and close the connection.
			//

			/*
			LINGER lingerStruct;
			lingerStruct.l_onoff = 1;
			lingerStruct.l_linger = 0;
			nRet = setsockopt(sdSocket, SOL_SOCKET, SO_LINGER,
			(char *)&lingerStruct, sizeof(lingerStruct));
			if( nRet == SOCKET_ERROR ) {
			debug("setsockopt(SO_LINGER) failed: %d\n", WSAGetLastError());
			return(sdSocket);
			}
			*/

			return(sdSocket);
		}

		template <typename T>
		inline bool read_and_close_iocp_socket(PPER_SOCKET_CONTEXT _lpPerSocketContext,
			PPER_IO_CONTEXT _lpIOContext, DWORD& _dwSendNumBytes, DWORD& _dwFlags,
			size_t keep_alive_max_count, T callback)
		{
			bool ret = false;

			IOCPStream strm(_lpPerSocketContext, _lpIOContext,
				_dwSendNumBytes, _dwFlags);
			if (keep_alive_max_count > 0) {
				auto last_connection = keep_alive_max_count == 1;
				auto connection_close = false;
				ret = callback(strm, last_connection, connection_close);
			}
			else {
				auto dummy_connection_close = false;
				ret = callback(strm, true, dummy_connection_close);
			}

			return ret;
		}
#endif

	} //detail
} //httplib