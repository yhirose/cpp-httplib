#pragma once
#include "httplib_typedefs.h"
#include "detail.h"
#include "iocp_types.h"
#include "Request.h"
#include "Response.h"
#include "Stream.h"
#include "IOCPStream.h"
#include "stream_line_reader.h"
#include <functional>
#include <regex>
#include <mutex>
#include <string>
#include <assert.h>
#include <vector>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <strsafe.h>
#include <MSWSock.h>
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

#define MAX_WORKER_THREAD 64

namespace httplib {
	class Server {
	public:
		typedef std::function<void(const httplib::Request&, httplib::Response&)> Handler;
		typedef std::function<void(const httplib::Request&, const httplib::Response&)> Logger;

#ifdef _WIN32
		typedef SOCKET socket_t;
#else
		typedef int socket_t;
#endif

		Server();

		virtual ~Server();

		virtual bool is_valid() const;

		Server& Get(const char* pattern, Handler handler);
		Server& Post(const char* pattern, Handler handler);

		Server& Put(const char* pattern, Handler handler);
		Server& Delete(const char* pattern, Handler handler);
		Server& Options(const char* pattern, Handler handler);

		bool set_base_dir(const char* path);

		void set_error_handler(Handler handler);
		void set_logger(Logger logger);

		void set_keep_alive_max_count(size_t count);

		int bind_to_any_port(const char* host, int socket_flags = 0);
		bool listen_after_bind();

		bool listen(const char* host, int port, int socket_flags = 0);

		bool is_running() const;
		void stop();

	protected:
		bool process_request(Stream& strm, bool last_connection, bool& connection_close);

		size_t keep_alive_max_count_;

	private:
		typedef std::vector<std::pair<std::regex, Handler>> Handlers;

		socket_t create_server_socket(const char* host, int port, int socket_flags);
		int bind_internal(const char* host, int port, int socket_flags);
		bool listen_internal();

		bool routing(Request& req, Response& res);
		bool handle_file_request(Request& req, Response& res);
		bool dispatch_request(Request& req, Response& res, Handlers& handlers);

		bool parse_request_line(const char* s, Request& req);
		void write_response(Stream& strm, bool last_connection, const Request& req, Response& res);


		virtual bool read_and_close_socket(socket_t sock);


		// TODO: Use thread pool... (Windows IOCP is as good as it gets on the platform!)
		Handlers    get_handlers_;
		Handlers    post_handlers_;
		Handlers    put_handlers_;
		Handlers    delete_handlers_;
		Handlers    options_handlers_;
		Handler     error_handler_;
		Logger      logger_;
		std::string base_dir_;
		socket_t    svr_sock_;
		bool        is_running_;
#ifndef CPPHTTPLIB_IOCP_SUPPORT 
		std::mutex  running_threads_mutex_;
		int         running_threads_;
#else
		//ADD IOCP GLOBALS IF IOCP SUPPORT
		BOOL CreateListenSocket(int port);
		BOOL CreateAcceptSocket(BOOL fUpdateIOCP);
		PPER_SOCKET_CONTEXT UpdateCompletionPort(SOCKET s, IO_OPERATION ClientIo, BOOL bAddToList);
		VOID CloseClient(PPER_SOCKET_CONTEXT lpPerSocketContext, BOOL bGraceful);

		PPER_SOCKET_CONTEXT CtxtAllocate(SOCKET s, IO_OPERATION ClientIO);
		VOID CtxtListFree();
		VOID CtxtListAddTo(PPER_SOCKET_CONTEXT lpPerSocketContext);
		VOID CtxtListDeleteFrom(PPER_SOCKET_CONTEXT lpPerSocketContext);

		static DWORD WINAPI WorkerThread(LPVOID WorkContext);

		HANDLE hIOCP_ = INVALID_HANDLE_VALUE;
		HANDLE hThreadHandles_[MAX_WORKER_THREAD];
		WSAEVENT hCleanupEvent_[1];
		PPER_SOCKET_CONTEXT pCtxtListenSocket_ = NULL;
		PPER_SOCKET_CONTEXT pCtxtList_ = NULL;
		CRITICAL_SECTION CriticalSection_;
#endif
	};

	inline Server::Server()
		: keep_alive_max_count_(5)
#ifndef CPPHTTPLIB_IOCP_SUPPORT
		, is_running_(false)
		, svr_sock_(INVALID_SOCKET)
		, running_threads_(0)
#endif
	{
#ifndef _WIN32
		signal(SIGPIPE, SIG_IGN);
#endif
	}

	inline Server::~Server() {}

	inline Server& Server::Get(const char* pattern, Handler handler)
	{
		get_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
		return *this;
	}

	inline Server& Server::Post(const char* pattern, Handler handler)
	{
		post_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
		return *this;
	}

	inline Server& Server::Put(const char* pattern, Handler handler)
	{
		put_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
		return *this;
	}

	inline Server& Server::Delete(const char* pattern, Handler handler)
	{
		delete_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
		return *this;
	}

	inline Server& Server::Options(const char* pattern, Handler handler)
	{
		options_handlers_.push_back(std::make_pair(std::regex(pattern), handler));
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

	inline void Server::set_keep_alive_max_count(size_t count)
	{
		keep_alive_max_count_ = count;
	}

	inline int Server::bind_to_any_port(const char* host, int socket_flags)
	{
		return bind_internal(host, 0, socket_flags);
	}

	inline bool Server::listen_after_bind() {
		return listen_internal();
	}

	inline bool Server::listen(const char* host, int port, int socket_flags)
	{
		if (bind_internal(host, port, socket_flags) < 0)
			return false;
		return listen_internal();
	}

	inline bool Server::is_running() const
	{
		return is_running_;
	}

	inline void Server::stop()
	{
		if (is_running_) {
			assert(svr_sock_ != INVALID_SOCKET);
			auto sock = svr_sock_;
			svr_sock_ = INVALID_SOCKET;
			detail::shutdown_socket(sock);
			detail::close_socket(sock);
		}
	}

	/*
	inline bool Server::is_running() const
	{
	return !g_bEndServer || g_bRestart;
	}

	inline void Server::stop()
	{
	if (g_bRestart) {
	assert(svr_sock_ != INVALID_SOCKET);
	auto sock = svr_sock_;
	svr_sock_ = INVALID_SOCKET;

	detail::shutdown_socket(sock);
	detail::close_socket(sock);
	}
	else
	{
	g_bEndServer = TRUE;
	WSASetEvent(hCleanupEvent_[0]);
	}
	}
	*/

	inline bool Server::parse_request_line(const char* s, httplib::Request& req)
	{
		static std::regex re("(GET|HEAD|POST|PUT|DELETE|OPTIONS) (([^?]+)(?:\\?(.+?))?) (HTTP/1\\.[01])\r\n");

		std::cmatch m;
		if (std::regex_match(s, m, re)) {
			req.version = std::string(m[5]);
			req.method = std::string(m[1]);
			req.target = std::string(m[2]);
			req.path = detail::decode_url(m[3]);

			// Parse query text
			auto len = std::distance(m[4].first, m[4].second);
			if (len > 0) {
				detail::parse_query_text(m[4], req.params);
			}

			return true;
		}

		return false;
	}

	inline void Server::write_response(Stream& strm, bool last_connection, const Request& req, Response& res)
	{
		assert(res.status != -1);

		if (400 <= res.status && error_handler_) {
			error_handler_(req, res);
		}

		// Response line
		strm.write_format("HTTP/1.1 %d %s\r\n",
			res.status,
			detail::status_message(res.status));

		// Headers
		if (last_connection ||
			req.get_header_value("Connection") == "close") {
			res.set_header("Connection", "close");
		}

		if (!last_connection &&
			req.get_header_value("Connection") == "Keep-Alive") {
			res.set_header("Connection", "Keep-Alive");
		}

		if (!res.body.empty()) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
			// TODO: 'Accpet-Encoding' has gzip, not gzip;q=0
			const auto& encodings = req.get_header_value("Accept-Encoding");
			if (encodings.find("gzip") != std::string::npos &&
				detail::can_compress(res.get_header_value("Content-Type"))) {
				detail::compress(res.body);
				res.set_header("Content-Encoding", "gzip");
			}
#endif

			if (!res.has_header("Content-Type")) {
				res.set_header("Content-Type", "text/plain");
			}

			auto length = std::to_string(res.body.size());
			res.set_header("Content-Length", length.c_str());
		}
		else if (res.streamcb) {
			// Streamed response
			bool chunked_response = !res.has_header("Content-Length");
			if (chunked_response)
				res.set_header("Transfer-Encoding", "chunked");
		}

		detail::write_headers(strm, res);

		// Body
		if (req.method != "HEAD") {
			if (!res.body.empty()) {
				strm.write(res.body.c_str(), res.body.size());
			}
			else if (res.streamcb) {
				bool chunked_response = !res.has_header("Content-Length");
				uint64_t offset = 0;
				bool data_available = true;
				while (data_available) {
					std::string chunk = res.streamcb(offset);
					offset += chunk.size();
					data_available = !chunk.empty();
					// Emit chunked response header and footer for each chunk
					if (chunked_response)
						chunk = detail::from_i_to_hex(chunk.size()) + "\r\n" + chunk + "\r\n";
					if (strm.write(chunk.c_str(), chunk.size()) < 0)
						break;  // Stop on error
				}
			}
		}

		// Log
		if (logger_) {
			logger_(req, res);
		}

#ifdef CPPHTTPLIB_IOCP_SUPPORT
		IOCPStream* s = dynamic_cast<IOCPStream*>(&strm);
		//CloseClient(s->getLpPerSocketContext(), TRUE);
		closesocket(s->getLpPerSocketContext()->Socket);
#endif
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
				auto type = detail::find_content_type(path);
				if (type) {
					res.set_header("Content-Type", type);
				}
				res.status = 200;
				return true;
			}
		}

		return false;
	}

	inline socket_t Server::create_server_socket(const char* host, int port, int socket_flags)
	{
#ifndef CPPHTTPLIB_IOCP_SUPPORT
		return detail::create_socket(host, port,
			[](socket_t sock, struct addrinfo& ai) -> bool {
			if (::bind(sock, ai.ai_addr, ai.ai_addrlen)) {
				return false;
			}
			if (::listen(sock, 5)) { // Listen through 5 channels
				return false;
			}
			return true;
		}, socket_flags);
#else
		WSADATA wsaData;
		int nRet = 0;
		SYSTEM_INFO systemInfo;
		DWORD dwThreadCount = 0;
		GetSystemInfo(&systemInfo);
		dwThreadCount = systemInfo.dwNumberOfProcessors * 2;

		hThreadHandles_[0] = (HANDLE)WSA_INVALID_EVENT;

		for (int i = 0; i < MAX_WORKER_THREAD; i++) {
			hThreadHandles_[i] = INVALID_HANDLE_VALUE;
		}


		if (WSA_INVALID_EVENT == (hCleanupEvent_[0] = WSACreateEvent()))
		{
		}

		if ((nRet = WSAStartup(0x202, &wsaData)) != 0) {
			if (hCleanupEvent_[0] != WSA_INVALID_EVENT) {
				WSACloseEvent(hCleanupEvent_[0]);
				hCleanupEvent_[0] = WSA_INVALID_EVENT;
			}
		}

		__try
		{
			InitializeCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			if (hCleanupEvent_[0] != WSA_INVALID_EVENT) {
				WSACloseEvent(hCleanupEvent_[0]);
				hCleanupEvent_[0] = WSA_INVALID_EVENT;
			}
		}
		//
		// notice that we will create more worker threads (dwThreadCount) than 
		// the thread concurrency limit on the IOCP.
		//
		hIOCP_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (hIOCP_ == NULL) {
		}

		for (DWORD dwCPU = 0; dwCPU<dwThreadCount; dwCPU++) {

			//
			// Create worker threads to service the overlapped I/O requests.  The decision
			// to create 2 worker threads per CPU in the system is a heuristic.  Also,
			// note that thread handles are closed right away, because we will not need them
			// and the worker threads will continue to execute.
			//
			HANDLE  hThread;
			DWORD   dwThreadId;

			hThread = CreateThread(NULL, 0, WorkerThread, hIOCP_, 0, &dwThreadId);
			if (hThread == NULL) {
			}
			hThreadHandles_[dwCPU] = hThread;
			hThread = INVALID_HANDLE_VALUE;
		}

		if (!CreateListenSocket(port))
		{
		}

		if (!CreateAcceptSocket(TRUE))
		{
		}
		return svr_sock_;
#endif
	}

	inline int Server::bind_internal(const char* host, int port, int socket_flags)
	{
		if (!is_valid()) {
			return -1;
		}

#ifndef CPPHTTPLIB_IOCP_SUPPORT
		svr_sock_ = create_server_socket(host, port, socket_flags);
		if (svr_sock_ == INVALID_SOCKET) {
			return -1;
		}

		if (port == 0) {
			struct sockaddr_storage address;
			socklen_t len = sizeof(address);
			if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr *>(&address), &len) == -1) {
				return -1;
			}
			if (address.ss_family == AF_INET) {
				return ntohs(reinterpret_cast<struct sockaddr_in*>(&address)->sin_port);
			}
			else if (address.ss_family == AF_INET6) {
				return ntohs(reinterpret_cast<struct sockaddr_in6*>(&address)->sin6_port);
			}
			else {
				return -1;
			}
		}
		else {
			return port;
		}
#else
		svr_sock_ = create_server_socket(host, port, socket_flags);
		if (svr_sock_ == INVALID_SOCKET) {
			return -1;
		}

		if (port == 0) {
			struct sockaddr_storage address;
			socklen_t len = sizeof(address);
			if (getsockname(svr_sock_, reinterpret_cast<struct sockaddr *>(&address), &len) == -1) {
				return -1;
			}
			if (address.ss_family == AF_INET) {
				return ntohs(reinterpret_cast<struct sockaddr_in*>(&address)->sin_port);
			}
			else if (address.ss_family == AF_INET6) {
				return ntohs(reinterpret_cast<struct sockaddr_in6*>(&address)->sin6_port);
			}
			else {
				return -1;
			}
		}
		else {
			return port;
		}
#endif
	}

	inline bool Server::listen_internal()
	{
		auto ret = true;

#ifndef CPPHTTPLIB_IOCP_SUPPORT
		is_running_ = true;

		for (;;) {
			auto val = detail::select_read(svr_sock_, 0, 100000);

			if (val == 0) { // Timeout
				if (svr_sock_ == INVALID_SOCKET) { //it just keeps going to read completed, change iocp method
												   // The server socket was closed by 'stop' method.
					break;
				}
				continue;
			}

			socket_t sock = accept(svr_sock_, NULL, NULL);

			if (sock == INVALID_SOCKET) {
				if (svr_sock_ != INVALID_SOCKET) {
					detail::close_socket(svr_sock_);
					ret = false;
				}
				else {
					; // The server socket was closed by user.
				}
				break;
			}

			// TODO: Use thread pool...
			std::thread([=]() {
				{
					std::lock_guard<std::mutex> guard(running_threads_mutex_);
					running_threads_++;
				}

				read_and_close_socket(sock);

				{
					std::lock_guard<std::mutex> guard(running_threads_mutex_);
					running_threads_--;
				}
			}).detach();
		}

		// TODO: Use thread pool...
		for (;;) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			std::lock_guard<std::mutex> guard(running_threads_mutex_);
			if (!running_threads_) {
				break;
			}
		}

		is_running_ = false;
#else //IOCP init and listen!
		SYSTEM_INFO systemInfo;
		DWORD dwThreadCount = 0;
		GetSystemInfo(&systemInfo);
		dwThreadCount = systemInfo.dwNumberOfProcessors * 2;
		while (is_running_)
		{
			WSAResetEvent(hCleanupEvent_[0]);

			__try
			{
				WSAWaitForMultipleEvents(1, hCleanupEvent_, TRUE, WSA_INFINITE, FALSE);
			}

			__finally
			{


				//
				// Cause worker threads to exit
				//
				if (hIOCP_) {
					for (DWORD i = 0; i < dwThreadCount; i++)
						PostQueuedCompletionStatus(hIOCP_, 0, 0, NULL);
				}

				//
				// Make sure worker threads exits.
				//
				if (WAIT_OBJECT_0 != WaitForMultipleObjects(dwThreadCount, hThreadHandles_, TRUE, 1000)) {}
				else
					for (DWORD i = 0; i<dwThreadCount; i++) {
						if (hThreadHandles_[i] != INVALID_HANDLE_VALUE)
							CloseHandle(hThreadHandles_[i]);
						hThreadHandles_[i] = INVALID_HANDLE_VALUE;
					}

				if (svr_sock_ != INVALID_SOCKET) {
					closesocket(svr_sock_);
					svr_sock_ = INVALID_SOCKET;
				}

				if (pCtxtListenSocket_) {
					//while (!HasOverlappedIoCompleted((LPOVERLAPPED)&pCtxtListenSocket_->pIOContext->Overlapped))
					//{
					//	Sleep(0);
					//}

					if (pCtxtListenSocket_->pIOContext->SocketAccept != INVALID_SOCKET)
						closesocket(pCtxtListenSocket_->pIOContext->SocketAccept);
					pCtxtListenSocket_->pIOContext->SocketAccept = INVALID_SOCKET;

					//
					// We know there is only one overlapped I/O on the listening socket
					//
					if (pCtxtListenSocket_->pIOContext)
						xfree(pCtxtListenSocket_->pIOContext);

					if (pCtxtListenSocket_)
						xfree(pCtxtListenSocket_);
					pCtxtListenSocket_ = NULL;
				}

				CtxtListFree();

				if (hIOCP_) {
					CloseHandle(hIOCP_);
					hIOCP_ = NULL;
				}
			} //finally
		} //while (g_bRestart)

		DeleteCriticalSection(&CriticalSection_);
		if (hCleanupEvent_[0] != WSA_INVALID_EVENT) {
			WSACloseEvent(hCleanupEvent_[0]);
			hCleanupEvent_[0] = WSA_INVALID_EVENT;
		}
		WSACleanup();
#endif

		return ret;
	}

	inline bool Server::routing(Request& req, Response& res)
	{
		if (req.method == "GET" && handle_file_request(req, res)) {
			return true;
		}

		if (req.method == "GET" || req.method == "HEAD") {
			return dispatch_request(req, res, get_handlers_);
		}
		else if (req.method == "POST") {
			return dispatch_request(req, res, post_handlers_);
		}
		else if (req.method == "PUT") {
			return dispatch_request(req, res, put_handlers_);
		}
		else if (req.method == "DELETE") {
			return dispatch_request(req, res, delete_handlers_);
		}
		else if (req.method == "OPTIONS") {
			return dispatch_request(req, res, options_handlers_);
		}
		return false;
	}

	inline bool Server::dispatch_request(Request& req, Response& res, Handlers& handlers)
	{
		for (const auto& x : handlers) {
			const auto& pattern = x.first;
			const auto& handler = x.second;

			if (std::regex_match(req.path, req.matches, pattern)) {
				handler(req, res);
				return true;
			}
		}
		return false;
	}

	inline bool Server::process_request(Stream& strm, bool last_connection, bool& connection_close)
	{
		const auto bufsiz = 2048;
		char buf[bufsiz];

		detail::stream_line_reader reader(strm, buf, bufsiz);

		// Connection has been closed on client
		if (!reader.getline()) {
			return false;
		}

		Request req;
		Response res;

		res.version = "HTTP/1.1";

		// Request line and headers
		if (!parse_request_line(reader.ptr(), req) || !detail::read_headers(strm, req.headers)) {
			res.status = 400;
			write_response(strm, last_connection, req, res);
			return true;
		}

		auto ret = true;
		if (req.get_header_value("Connection") == "close") {
			// ret = false;
			connection_close = true;
		}

		req.set_header("REMOTE_ADDR", strm.get_remote_addr().c_str());

		// Body
		if (req.method == "POST" || req.method == "PUT") {
			if (!detail::read_content(strm, req, req.progress)) {
				res.status = 400;
				write_response(strm, last_connection, req, res);
				return ret;
			}

			const auto& content_type = req.get_header_value("Content-Type");

			if (req.get_header_value("Content-Encoding") == "gzip") {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
				detail::decompress(req.body);
#else
				res.status = 415;
				write_response(strm, last_connection, req, res);
				return ret;
#endif
			}

			if (!content_type.find("application/x-www-form-urlencoded")) {
				detail::parse_query_text(req.body, req.params);
			}
			else if (!content_type.find("multipart/form-data")) {
				std::string boundary;
				if (!detail::parse_multipart_boundary(content_type, boundary) ||
					!detail::parse_multipart_formdata(boundary, req.body, req.files)) {
					res.status = 400;
					write_response(strm, last_connection, req, res);
					return ret;
				}
			}
		}

		if (routing(req, res)) {
			if (res.status == -1) {
				res.status = 200;
			}
		}
		else {
			res.status = 404;
		}

		write_response(strm, last_connection, req, res);
		return ret;
	}

	inline bool Server::is_valid() const
	{
		return true;
	}

	inline bool Server::read_and_close_socket(socket_t sock)
	{
		return detail::read_and_close_socket(
			sock,
			keep_alive_max_count_,
			[this](Stream& strm, bool last_connection, bool& connection_close) {
			return process_request(strm, last_connection, connection_close);
		});
	}


	//
	// Worker thread that handles all I/O requests on any socket handle added to the IOCP.
	//
#ifdef CPPHTTPLIB_IOCP_SUPPORT
	//
	//  Create a listening socket, bind, and set up its listening backlog.
	//
	BOOL httplib::Server::CreateListenSocket(int port) {
		std::string p = std::to_string(port);
		int nRet = 0;
		LINGER lingerStruct;
		struct addrinfo hints = { 0 };
		struct addrinfo *addrlocal = NULL;

		lingerStruct.l_onoff = 1;
		lingerStruct.l_linger = 0;

		hints.ai_flags = 0; //0? AI_PASSIVE
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(NULL, p.c_str(), &hints, &addrlocal) != 0) {
			return(FALSE);
		}

		if (addrlocal == NULL) {
			return(FALSE);
		}

		svr_sock_ = httplib::detail::CreateSocket();
		if (svr_sock_ == INVALID_SOCKET) {
			freeaddrinfo(addrlocal);
			return(FALSE);
		}

		nRet = bind(svr_sock_, addrlocal->ai_addr, (int)addrlocal->ai_addrlen);
		if (nRet == SOCKET_ERROR) {
			freeaddrinfo(addrlocal);
			return(FALSE);
		}

		nRet = ::listen(svr_sock_, 5);
		if (nRet == SOCKET_ERROR) {
			freeaddrinfo(addrlocal);
			return(FALSE);
		}

		freeaddrinfo(addrlocal);

		return(TRUE);
	}

	BOOL httplib::Server::CreateAcceptSocket(BOOL fUpdateIOCP) {
		int nRet = 0;
		DWORD dwRecvNumBytes = 0;
		DWORD bytes = 0;

		GUID acceptex_guid = WSAID_ACCEPTEX;

		if (fUpdateIOCP) {
			pCtxtListenSocket_ = UpdateCompletionPort(svr_sock_, ClientIoAccept, FALSE);
			if (pCtxtListenSocket_ == NULL) {
				return(FALSE);
			}

			// Load the AcceptEx extension function from the provider for this socket
			nRet = WSAIoctl(
				svr_sock_,
				SIO_GET_EXTENSION_FUNCTION_POINTER,
				&acceptex_guid,
				sizeof(acceptex_guid),
				&pCtxtListenSocket_->fnAcceptEx,
				sizeof(pCtxtListenSocket_->fnAcceptEx),
				&bytes,
				NULL,
				NULL
			);
			if (nRet == SOCKET_ERROR)
			{
				return (FALSE);
			}
		}

		pCtxtListenSocket_->pIOContext->SocketAccept = httplib::detail::CreateSocket();
		if (pCtxtListenSocket_->pIOContext->SocketAccept == INVALID_SOCKET) {
			return(FALSE);
		}

		nRet = pCtxtListenSocket_->fnAcceptEx(svr_sock_, pCtxtListenSocket_->pIOContext->SocketAccept,
			(LPVOID)(pCtxtListenSocket_->pIOContext->Buffer),
			0, //MAX_BUFF_SIZE - (2 * (sizeof(SOCKADDR_STORAGE) + 16)),
			sizeof(SOCKADDR_STORAGE) + 16, sizeof(SOCKADDR_STORAGE) + 16,
			&dwRecvNumBytes,
			(LPOVERLAPPED) &(pCtxtListenSocket_->pIOContext->Overlapped));
		if (nRet == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
			return(FALSE);
		}

		return(TRUE);
	}

	//
	//  Allocate a context structures for the socket and add the socket to the IOCP.  
	//  Additionally, add the context structure to the global list of context structures.
	//
	PPER_SOCKET_CONTEXT httplib::Server::UpdateCompletionPort(SOCKET sd, IO_OPERATION ClientIo,
		BOOL bAddToList)
	{
		PPER_SOCKET_CONTEXT lpPerSocketContext;

		lpPerSocketContext = CtxtAllocate(sd, ClientIo);
		if (lpPerSocketContext == NULL)
			return(NULL);

		hIOCP_ = CreateIoCompletionPort((HANDLE)sd, hIOCP_, (DWORD_PTR)lpPerSocketContext, 0);
		if (hIOCP_ == NULL) {
			if (lpPerSocketContext->pIOContext)
				xfree(lpPerSocketContext->pIOContext);
			xfree(lpPerSocketContext);
			return(NULL);
		}

		//
		//The listening socket context (bAddToList is FALSE) is not added to the list.
		//All other socket contexts are added to the list.
		//
		if (bAddToList) CtxtListAddTo(lpPerSocketContext);

		return(lpPerSocketContext);
	}

	//
	//  Close down a connection with a client.  This involves closing the socket (when 
	//  initiated as a result of a CTRL-C the socket closure is not graceful).  Additionally, 
	//  any context data associated with that socket is free'd.
	//
	VOID httplib::Server::CloseClient(PPER_SOCKET_CONTEXT lpPerSocketContext, BOOL bGraceful)
	{
		__try
		{
			EnterCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}

		if (lpPerSocketContext) {
			if (!bGraceful) {

				//
				// force the subsequent closesocket to be abortative.
				//
				LINGER  lingerStruct;

				lingerStruct.l_onoff = 1;
				lingerStruct.l_linger = 0;
				setsockopt(lpPerSocketContext->Socket, SOL_SOCKET, SO_LINGER,
					(char *)&lingerStruct, sizeof(lingerStruct));
			}
			if (lpPerSocketContext->pIOContext->SocketAccept != INVALID_SOCKET) {
				closesocket(lpPerSocketContext->pIOContext->SocketAccept);
				lpPerSocketContext->pIOContext->SocketAccept = INVALID_SOCKET;
			};

			closesocket(lpPerSocketContext->Socket);
			lpPerSocketContext->Socket = INVALID_SOCKET;
			CtxtListDeleteFrom(lpPerSocketContext);
			lpPerSocketContext = NULL;
		}

		LeaveCriticalSection(&CriticalSection_);

		return;
	}

	//
	// Allocate a socket context for the new connection.  
	//
	PPER_SOCKET_CONTEXT httplib::Server::CtxtAllocate(SOCKET sd, IO_OPERATION ClientIO)
	{
		PPER_SOCKET_CONTEXT lpPerSocketContext;

		__try
		{
			EnterCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return NULL;
		}

		lpPerSocketContext = (PPER_SOCKET_CONTEXT)xmalloc(sizeof(PER_SOCKET_CONTEXT));
		if (lpPerSocketContext) {
			lpPerSocketContext->pIOContext = (PPER_IO_CONTEXT)xmalloc(sizeof(PER_IO_CONTEXT));
			if (lpPerSocketContext->pIOContext)
			{
				lpPerSocketContext->Socket = sd;

				lpPerSocketContext->lpIOCPServer = this;

				lpPerSocketContext->pCtxtBack = NULL;
				lpPerSocketContext->pCtxtForward = NULL;

				lpPerSocketContext->pIOContext->Overlapped.Internal = 0;
				lpPerSocketContext->pIOContext->Overlapped.InternalHigh = 0;
				lpPerSocketContext->pIOContext->Overlapped.Offset = 0;
				lpPerSocketContext->pIOContext->Overlapped.OffsetHigh = 0;
				lpPerSocketContext->pIOContext->Overlapped.hEvent = NULL;

				lpPerSocketContext->pIOContext->IOOperation = ClientIO;

				lpPerSocketContext->pIOContext->pIOContextForward = NULL;

				lpPerSocketContext->pIOContext->nTotalBytes = 0;
				lpPerSocketContext->pIOContext->nSentBytes = 0;

				lpPerSocketContext->pIOContext->wsabuf.buf = lpPerSocketContext->pIOContext->Buffer;
				lpPerSocketContext->pIOContext->wsabuf.len = sizeof(lpPerSocketContext->pIOContext->Buffer);

				lpPerSocketContext->pIOContext->SocketAccept = INVALID_SOCKET;

				ZeroMemory(lpPerSocketContext->pIOContext->wsabuf.buf, lpPerSocketContext->pIOContext->wsabuf.len);
				}
			else {
				xfree(lpPerSocketContext);
			}

			}
		else {
			return(NULL);
		}

		LeaveCriticalSection(&CriticalSection_);

		return(lpPerSocketContext);
		}

	//
	//  Add a client connection context structure to the global list of context structures.
	//
	VOID httplib::Server::CtxtListAddTo(PPER_SOCKET_CONTEXT lpPerSocketContext) {
		PPER_SOCKET_CONTEXT pTemp;

		__try
		{
			EnterCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}

		if (pCtxtList_ == NULL) {

			//
			// add the first node to the linked list
			//
			lpPerSocketContext->pCtxtBack = NULL;
			lpPerSocketContext->pCtxtForward = NULL;
			pCtxtList_ = lpPerSocketContext;
		}
		else {

			//
			// add node to head of list
			//
			pTemp = pCtxtList_;

			pCtxtList_ = lpPerSocketContext;
			lpPerSocketContext->pCtxtBack = pTemp;
			lpPerSocketContext->pCtxtForward = NULL;

			pTemp->pCtxtForward = lpPerSocketContext;
		}

		LeaveCriticalSection(&CriticalSection_);

		return;
	}

	//
	//  Remove a client context structure from the global list of context structures.
	//
	VOID httplib::Server::CtxtListDeleteFrom(PPER_SOCKET_CONTEXT lpPerSocketContext) {
		PPER_SOCKET_CONTEXT pBack;
		PPER_SOCKET_CONTEXT pForward;
		PPER_IO_CONTEXT     pNextIO = NULL;
		PPER_IO_CONTEXT     pTempIO = NULL;

		__try
		{
			EnterCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}

		if (lpPerSocketContext) {
			pBack = lpPerSocketContext->pCtxtBack;
			pForward = lpPerSocketContext->pCtxtForward;

			if (pBack == NULL && pForward == NULL) {

				//
				// This is the only node in the list to delete
				//
				pCtxtList_ = NULL;
			}
			else if (pBack == NULL && pForward != NULL) {

				//
				// This is the start node in the list to delete
				//
				pForward->pCtxtBack = NULL;
				pCtxtList_ = pForward;
			}
			else if (pBack != NULL && pForward == NULL) {

				//
				// This is the end node in the list to delete
				//
				pBack->pCtxtForward = NULL;
			}
			else if (pBack && pForward) {

				//
				// Neither start node nor end node in the list
				//
				pBack->pCtxtForward = pForward;
				pForward->pCtxtBack = pBack;
			}

			//
			// Free all i/o context structures per socket
			//
			pTempIO = (PPER_IO_CONTEXT)(lpPerSocketContext->pIOContext);
			do {
				pNextIO = (PPER_IO_CONTEXT)(pTempIO->pIOContextForward);
				if (pTempIO) {

					//
					//The overlapped structure is safe to free when only the posted i/o has
					//completed. Here we only need to test those posted but not yet received 
					//by PQCS in the shutdown process.
					//
					if (!is_running_)
					{
						while (!HasOverlappedIoCompleted((LPOVERLAPPED)pTempIO))
						{
							Sleep(0);
						}
						xfree(pTempIO);
						pTempIO = NULL;
					}
				}
				pTempIO = pNextIO;
			} while (pNextIO);

			xfree(lpPerSocketContext);
			lpPerSocketContext = NULL;
		}

		LeaveCriticalSection(&CriticalSection_);

		return;
	}

	//
	//  Free all context structure in the global list of context structures.
	//
	VOID httplib::Server::CtxtListFree() {
		PPER_SOCKET_CONTEXT pTemp1, pTemp2;

		__try
		{
			EnterCriticalSection(&CriticalSection_);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}

		pTemp1 = pCtxtList_;
		while (pTemp1) {
			pTemp2 = pTemp1->pCtxtBack;
			CloseClient(pTemp1, FALSE);
			pTemp1 = pTemp2;
		}

		LeaveCriticalSection(&CriticalSection_);

		return;
	}

	DWORD WINAPI Server::WorkerThread(LPVOID WorkThreadContext) {

		HANDLE hIOCP = (HANDLE)WorkThreadContext;
		BOOL bSuccess = FALSE;
		int nRet = 0;
		LPWSAOVERLAPPED lpOverlapped = NULL;
		PPER_SOCKET_CONTEXT lpPerSocketContext = NULL;
		PPER_SOCKET_CONTEXT lpAcceptSocketContext = NULL;
		PPER_IO_CONTEXT lpIOContext = NULL;
		WSABUF buffRecv;
		WSABUF buffSend;
		DWORD dwRecvNumBytes = 0;
		DWORD dwSendNumBytes = 0;
		DWORD dwFlags = 0;
		DWORD dwIoSize = 0;
		HRESULT hRet;

		while (TRUE) {

			//
			// continually loop to service io completion packets
			//
			bSuccess = GetQueuedCompletionStatus(
				hIOCP,
				&dwIoSize,
				(PDWORD_PTR)&lpPerSocketContext,
				(LPOVERLAPPED *)&lpOverlapped,
				INFINITE
			);

			if (lpPerSocketContext == NULL) {

				//
				// CTRL-C handler used PostQueuedCompletionStatus to post an I/O packet with
				// a NULL CompletionKey (or if we get one for any reason).  It is time to exit.
				//
				return(0);
			}

			if (!lpPerSocketContext->lpIOCPServer->is_running_) {

				//
				// main thread will do all cleanup needed - see finally block
				//
				return(0);
			}

			lpIOContext = (PPER_IO_CONTEXT)lpOverlapped;

			//
			//We should never skip the loop and not post another AcceptEx if the current
			//completion packet is for previous AcceptEx
			//
			if (lpIOContext->IOOperation != ClientIoAccept) {
				if (!bSuccess || (bSuccess && (0 == dwIoSize))) {

					//
					// client connection dropped, continue to service remaining (and possibly 
					// new) client connections
					//
					lpPerSocketContext->lpIOCPServer->CloseClient(lpPerSocketContext, FALSE);
					continue;
				}
			}

			//
			// determine what type of IO packet has completed by checking the PER_IO_CONTEXT 
			// associated with this socket.  This will determine what action to take.
			//
			switch (lpIOContext->IOOperation) {
			case ClientIoAccept:
				//
				// When the AcceptEx function returns, the socket sAcceptSocket is 
				// in the default state for a connected socket. The socket sAcceptSocket 
				// does not inherit the properties of the socket associated with 
				// sListenSocket parameter until SO_UPDATE_ACCEPT_CONTEXT is set on 
				// the socket. Use the setsockopt function to set the SO_UPDATE_ACCEPT_CONTEXT 
				// option, specifying sAcceptSocket as the socket handle and sListenSocket 
				// as the option value. 
				//
				nRet = setsockopt(
					lpPerSocketContext->pIOContext->SocketAccept,
					SOL_SOCKET,
					SO_UPDATE_ACCEPT_CONTEXT,
					(char *)&lpPerSocketContext->lpIOCPServer->svr_sock_,
					sizeof(lpPerSocketContext->lpIOCPServer->svr_sock_)
				);

				if (nRet == SOCKET_ERROR) {

					//
					//just warn user here.
					//
					WSASetEvent(lpPerSocketContext->lpIOCPServer->hCleanupEvent_[0]);
					return(0);
				}

				lpAcceptSocketContext = lpPerSocketContext->lpIOCPServer->UpdateCompletionPort(
					lpPerSocketContext->pIOContext->SocketAccept,
					ClientIoAccept, TRUE);

				if (lpAcceptSocketContext == NULL) {

					//
					//just warn user here.
					//
					WSASetEvent(lpPerSocketContext->lpIOCPServer->hCleanupEvent_[0]);
					return(0);
				}

				if (dwIoSize) {
					lpAcceptSocketContext->pIOContext->IOOperation = ClientIoWrite;
					lpAcceptSocketContext->pIOContext->nTotalBytes = dwIoSize;
					lpAcceptSocketContext->pIOContext->nSentBytes = 0;
					lpAcceptSocketContext->pIOContext->wsabuf.len = dwIoSize;
					hRet = StringCbCopyN((STRSAFE_LPWSTR)lpAcceptSocketContext->pIOContext->Buffer,
						MAX_BUFF_SIZE,
						(STRSAFE_PCNZWCH)lpPerSocketContext->pIOContext->Buffer,
						sizeof(lpPerSocketContext->pIOContext->Buffer)
					);
					lpAcceptSocketContext->pIOContext->wsabuf.buf = lpAcceptSocketContext->pIOContext->Buffer;

					nRet = WSASend(
						lpPerSocketContext->pIOContext->SocketAccept,
						&lpAcceptSocketContext->pIOContext->wsabuf, 1,
						&dwSendNumBytes,
						0,
						&(lpAcceptSocketContext->pIOContext->Overlapped), NULL);

					if (nRet == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
						lpPerSocketContext->lpIOCPServer->CloseClient(lpAcceptSocketContext, FALSE);
					}
				}
				else {

					//
					// AcceptEx completes but doesn't read any data so we need to post
					// an outstanding overlapped read.
					//
					lpAcceptSocketContext->pIOContext->IOOperation = ClientIoRead;
					dwRecvNumBytes = 0;
					dwFlags = 0;
					buffRecv.buf = lpAcceptSocketContext->pIOContext->Buffer,
						buffRecv.len = MAX_BUFF_SIZE;
					nRet = WSARecv(
						lpAcceptSocketContext->Socket,
						&buffRecv, 1,
						&dwRecvNumBytes,
						&dwFlags,
						&lpAcceptSocketContext->pIOContext->Overlapped, NULL);
					if (nRet == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
						lpPerSocketContext->lpIOCPServer->CloseClient(lpAcceptSocketContext, FALSE);
					}
				}

				//
				//Time to post another outstanding AcceptEx
				//
				if (!lpPerSocketContext->lpIOCPServer->CreateAcceptSocket(FALSE)) {
					WSASetEvent(lpPerSocketContext->lpIOCPServer->hCleanupEvent_[0]);
					return(0);
				}
				break;

			case ClientIoRead:
				//
				// a read operation has completed, feed the wsadata
				// to the httplib system, plugin the WSASend
				// inside the httplib system as replacement for
				// to send the response
				//
				lpIOContext->IOOperation = ClientIoWrite;
				lpIOContext->nTotalBytes = dwIoSize;
				lpIOContext->nSentBytes = 0;
				lpIOContext->wsabuf.len = dwIoSize;
				dwFlags = 0;

				httplib::detail::read_and_close_iocp_socket(lpPerSocketContext, lpIOContext,
					dwRecvNumBytes, dwFlags, 5,
					[&lpPerSocketContext](httplib::Stream& strm, bool last_connection, bool& connection_close) {
					return lpPerSocketContext->lpIOCPServer->process_request(strm, last_connection, connection_close);
				});
				break;

			case ClientIoWrite:
				//
				// a write operation has completed, determine if all the data intended to be
				// sent actually was sent.
				//
				lpIOContext->nSentBytes += dwIoSize;
				dwFlags = 0;
				if (lpIOContext->nSentBytes < lpIOContext->nTotalBytes) {
					//
					// the previous write operation didn't send all the data,
					// post another send to complete the operation
					//
					lpIOContext->IOOperation = ClientIoWrite;
					buffSend.buf = lpIOContext->Buffer + lpIOContext->nSentBytes;
					buffSend.len = lpIOContext->nTotalBytes - lpIOContext->nSentBytes;
					nRet = WSASend(
						lpPerSocketContext->Socket,
						&buffSend, 1, &dwSendNumBytes,
						dwFlags,
						&(lpIOContext->Overlapped), NULL);
					if (nRet == SOCKET_ERROR && (ERROR_IO_PENDING != WSAGetLastError())) {
						lpPerSocketContext->lpIOCPServer->CloseClient(lpPerSocketContext, FALSE);
					}
				}
				else {
					//
					// previous write operation completed for this socket,
					//
				}
				break;

			} //switch
		} //while
		return(0);
	}
#endif
};