#pragma once
#include "str_case_cmp.h"
#include "httplib_typedefs.h"
#include "Request.h"
#include "Response.h"
#include "Stream.h"
#include <string>
#include <map>


namespace httplib {
	class Client {
	public:
		Client(
			const char* host,
			int port = 80,
			time_t timeout_sec = 300);

		virtual ~Client();

		virtual bool is_valid() const;

		std::shared_ptr<Response> Get(const char* path, Progress progress = nullptr);
		std::shared_ptr<Response> Get(const char* path, const Headers& headers, Progress progress = nullptr);

		std::shared_ptr<Response> Head(const char* path);
		std::shared_ptr<Response> Head(const char* path, const Headers& headers);

		std::shared_ptr<Response> Post(const char* path, const std::string& body, const char* content_type);
		std::shared_ptr<Response> Post(const char* path, const Headers& headers, const std::string& body, const char* content_type);

		std::shared_ptr<Response> Post(const char* path, const Params& params);
		std::shared_ptr<Response> Post(const char* path, const Headers& headers, const Params& params);

		std::shared_ptr<Response> Put(const char* path, const std::string& body, const char* content_type);
		std::shared_ptr<Response> Put(const char* path, const Headers& headers, const std::string& body, const char* content_type);

		std::shared_ptr<Response> Delete(const char* path);
		std::shared_ptr<Response> Delete(const char* path, const Headers& headers);

		std::shared_ptr<Response> Options(const char* path);
		std::shared_ptr<Response> Options(const char* path, const Headers& headers);

		bool send(Request& req, Response& res);

	protected:
		bool process_request(Stream& strm, Request& req, Response& res, bool& connection_close);

		const std::string host_;
		const int         port_;
		time_t            timeout_sec_;
		const std::string host_and_port_;

	private:
		socket_t create_client_socket() const;
		bool read_response_line(Stream& strm, Response& res);
		void write_request(Stream& strm, Request& req);

		virtual bool read_and_close_socket(socket_t sock, Request& req, Response& res);
	};

	inline Client::Client(
		const char* host, int port, time_t timeout_sec)
		: host_(host)
		, port_(port)
		, timeout_sec_(timeout_sec)
		, host_and_port_(host_ + ":" + std::to_string(port_))
	{
	}

	inline Client::~Client()
	{
	}

	inline bool Client::is_valid() const
	{
		return true;
	}

	inline socket_t Client::create_client_socket() const
	{
		return detail::create_socket(host_.c_str(), port_,
			[=](socket_t sock, struct addrinfo& ai) -> bool {
			detail::set_nonblocking(sock, true);
			auto ret = connect(sock, ai.ai_addr, ai.ai_addrlen);
			if (ret < 0) {
				if (detail::is_connection_error() ||
					!detail::wait_until_socket_is_ready(sock, timeout_sec_, 0)) {
					detail::close_socket(sock);
					return false;
				}
			}

			detail::set_nonblocking(sock, false);
			return true;
		});
	}

	inline bool Client::read_response_line(Stream& strm, Response& res)
	{
		const auto bufsiz = 2048;
		char buf[bufsiz];

		detail::stream_line_reader reader(strm, buf, bufsiz);

		if (!reader.getline()) {
			return false;
		}

		const static std::regex re("(HTTP/1\\.[01]) (\\d+?) .+\r\n");

		std::cmatch m;
		if (std::regex_match(reader.ptr(), m, re)) {
			res.version = std::string(m[1]);
			res.status = std::stoi(std::string(m[2]));
		}

		return true;
	}

	inline bool Client::send(Request& req, Response& res)
	{
		if (req.path.empty()) {
			return false;
		}

		auto sock = create_client_socket();
		if (sock == INVALID_SOCKET) {
			return false;
		}

		return read_and_close_socket(sock, req, res);
	}

	inline void Client::write_request(Stream& strm, Request& req)
	{
		auto path = detail::encode_url(req.path);

		// Request line
		strm.write_format("%s %s HTTP/1.1\r\n",
			req.method.c_str(),
			path.c_str());

		// Headers
		req.set_header("Host", host_and_port_.c_str());

		if (!req.has_header("Accept")) {
			req.set_header("Accept", "*/*");
		}

		if (!req.has_header("User-Agent")) {
			req.set_header("User-Agent", "cpp-httplib/0.2");
		}

		// TODO: Support KeepAlive connection
		// if (!req.has_header("Connection")) {
		req.set_header("Connection", "close");
		// }

		if (!req.body.empty()) {
			if (!req.has_header("Content-Type")) {
				req.set_header("Content-Type", "text/plain");
			}

			auto length = std::to_string(req.body.size());
			req.set_header("Content-Length", length.c_str());
		}

		detail::write_headers(strm, req);

		// Body
		if (!req.body.empty()) {
			if (req.get_header_value("Content-Type") == "application/x-www-form-urlencoded") {
				auto str = detail::encode_url(req.body);
				strm.write(str.c_str(), str.size());
			}
			else {
				strm.write(req.body.c_str(), req.body.size());
			}
		}
	}

	inline bool Client::process_request(Stream& strm, Request& req, Response& res, bool& connection_close)
	{
		// Send request
		write_request(strm, req);

		// Receive response and headers
		if (!read_response_line(strm, res) || !detail::read_headers(strm, res.headers)) {
			return false;
		}

		if (res.get_header_value("Connection") == "close" || res.version == "HTTP/1.0") {
			connection_close = true;
		}

		// Body
		if (req.method != "HEAD") {
			if (!detail::read_content(strm, res, req.progress)) {
				return false;
			}

			if (res.get_header_value("Content-Encoding") == "gzip") {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
				detail::decompress(res.body);
#else
				return false;
#endif
			}
		}

		return true;
	}

	inline bool Client::read_and_close_socket(socket_t sock, Request& req, Response& res)
	{
		return detail::read_and_close_socket(
			sock,
			0,
			[&](Stream& strm, bool /*last_connection*/, bool& connection_close) {
			return process_request(strm, req, res, connection_close);
		});
	}

	inline std::shared_ptr<Response> Client::Get(const char* path, Progress progress)
	{
		return Get(path, Headers(), progress);
	}

	inline std::shared_ptr<Response> Client::Get(const char* path, const Headers& headers, Progress progress)
	{
		Request req;
		req.method = "GET";
		req.path = path;
		req.headers = headers;
		req.progress = progress;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}

	inline std::shared_ptr<Response> Client::Head(const char* path)
	{
		return Head(path, Headers());
	}

	inline std::shared_ptr<Response> Client::Head(const char* path, const Headers& headers)
	{
		Request req;
		req.method = "HEAD";
		req.headers = headers;
		req.path = path;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}

	inline std::shared_ptr<Response> Client::Post(
		const char* path, const std::string& body, const char* content_type)
	{
		return Post(path, Headers(), body, content_type);
	}

	inline std::shared_ptr<Response> Client::Post(
		const char* path, const Headers& headers, const std::string& body, const char* content_type)
	{
		Request req;
		req.method = "POST";
		req.headers = headers;
		req.path = path;

		req.headers.emplace("Content-Type", content_type);
		req.body = body;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}

	inline std::shared_ptr<Response> Client::Post(const char* path, const Params& params)
	{
		return Post(path, Headers(), params);
	}

	inline std::shared_ptr<Response> Client::Post(const char* path, const Headers& headers, const Params& params)
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

		return Post(path, headers, query, "application/x-www-form-urlencoded");
	}

	inline std::shared_ptr<Response> Client::Put(
		const char* path, const std::string& body, const char* content_type)
	{
		return Put(path, Headers(), body, content_type);
	}

	inline std::shared_ptr<Response> Client::Put(
		const char* path, const Headers& headers, const std::string& body, const char* content_type)
	{
		Request req;
		req.method = "PUT";
		req.headers = headers;
		req.path = path;

		req.headers.emplace("Content-Type", content_type);
		req.body = body;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}

	inline std::shared_ptr<Response> Client::Delete(const char* path)
	{
		return Delete(path, Headers());
	}

	inline std::shared_ptr<Response> Client::Delete(const char* path, const Headers& headers)
	{
		Request req;
		req.method = "DELETE";
		req.path = path;
		req.headers = headers;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}

	inline std::shared_ptr<Response> Client::Options(const char* path)
	{
		return Options(path, Headers());
	}

	inline std::shared_ptr<Response> Client::Options(const char* path, const Headers& headers)
	{
		Request req;
		req.method = "OPTIONS";
		req.path = path;
		req.headers = headers;

		auto res = std::make_shared<Response>();

		return send(req, *res) ? res : nullptr;
	}
};