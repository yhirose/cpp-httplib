#pragma once

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

#include "Server.h"
#include <openssl/ssl.h>
#include <mutex>

namespace httplib {
	class SSLServer : public Server {
	public:
		SSLServer(
			const char* cert_path, const char* private_key_path);

		virtual ~SSLServer();

		virtual bool is_valid() const;

	private:
		virtual bool read_and_close_socket(socket_t sock);

		SSL_CTX* ctx_;
		std::mutex ctx_mutex_;
	};

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

			{
				int eccert = SSL_CTX_use_certificate_file(ctx_, cert_path, SSL_FILETYPE_PEM);
				if (!eccert) {
					printf("Error - check the path to your cert. Your cert may also be invalid.\n\n");
				}

				int ecpkey = SSL_CTX_use_PrivateKey_file(ctx_, private_key_path, SSL_FILETYPE_PEM);
				if (!ecpkey) {
					printf("Error - check the path to your private key. Your private key may also be invalid\n\n");
				}

				if (!eccert || !ecpkey) {
					SSL_CTX_free(ctx_);
					printf("The program will exit.\n\n\t");
					system("pause");
					ctx_ = nullptr;
				}
			}
		}
	}

	inline SSLServer::~SSLServer()
	{
		if (ctx_) {
			SSL_CTX_free(ctx_);
		}
	}

	inline bool SSLServer::is_valid() const
	{
		return ctx_;
	}

	inline bool SSLServer::read_and_close_socket(socket_t sock)
	{
		return detail::read_and_close_socket_ssl(
			sock,
			keep_alive_max_count_,
			ctx_, ctx_mutex_,
			SSL_accept,
			[](SSL* /*ssl*/) {},
			[this](Stream& strm, bool last_connection, bool& connection_close) {
			return process_request(strm, last_connection, connection_close);
		});
	}
};

#endif