#pragma once

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

#include "Stream.h"
#include <openssl/ssl.h>
#include <string>

namespace httplib {
	class SSLSocketStream : public Stream {
	public:
		SSLSocketStream(socket_t sock, SSL* ssl);
		virtual ~SSLSocketStream();

		virtual int read(char* ptr, size_t size);
		virtual int write(const char* ptr, size_t size);
		virtual int write(const char* ptr);
		virtual std::string get_remote_addr();

	private:
		socket_t sock_;
		SSL* ssl_;
	};

	inline SSLSocketStream::SSLSocketStream(socket_t sock, SSL* ssl)
		: sock_(sock), ssl_(ssl)
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

	inline std::string SSLSocketStream::get_remote_addr() {
		return detail::get_remote_addr(sock_);
	}
};

#endif