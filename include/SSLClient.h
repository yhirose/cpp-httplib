#pragma once


#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

#include "detail.h"
#include "Request.h"
#include "Response.h"
#include "Client.h"
#include <openssl/ssl.h>
#include <mutex>

namespace httplib {
	class SSLClient : public Client {
	public:
		SSLClient(
			const char* host,
			int port = 80,
			time_t timeout_sec = 300);

		virtual ~SSLClient();

		virtual bool is_valid() const;

	private:
		virtual bool read_and_close_socket(socket_t sock, Request& req, Response& res);

		SSL_CTX* ctx_;
		std::mutex ctx_mutex_;
	};

	inline SSLClient::SSLClient(const char* host, int port, time_t timeout_sec)
		: Client(host, port, timeout_sec)
	{
		ctx_ = SSL_CTX_new(SSLv23_client_method());
	}

	inline SSLClient::~SSLClient()
	{
		if (ctx_) {
			SSL_CTX_free(ctx_);
		}
	}

	inline bool SSLClient::is_valid() const
	{
		return ctx_;
	}

	inline bool SSLClient::read_and_close_socket(socket_t sock, Request& req, Response& res)
	{
		return is_valid() && detail::read_and_close_socket_ssl(
			sock, 0,
			ctx_, ctx_mutex_,
			SSL_connect,
			[&](SSL* ssl) {
			SSL_set_tlsext_host_name(ssl, host_.c_str());
		},
			[&](Stream& strm, bool /*last_connection*/, bool& connection_close) {
			return process_request(strm, req, res, connection_close);
		});
	}
};

#endif