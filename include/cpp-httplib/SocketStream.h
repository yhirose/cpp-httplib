#pragma once
#include "httplib_typedefs.h"
#include "detail.h"
#include "Stream.h"

namespace httplib {

	namespace detail {
		std::string get_remote_addr(socket_t sock);
	};

	class SocketStream : public Stream {
	public:
		SocketStream(socket_t sock);
		virtual ~SocketStream();

		virtual int read(char* ptr, size_t size);
		virtual int write(const char* ptr, size_t size);
		virtual int write(const char* ptr);
		virtual std::string get_remote_addr();

	private:
		socket_t sock_;
	};

	inline SocketStream::SocketStream(socket_t sock) : sock_(sock) {}

	inline SocketStream::~SocketStream() {}

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

	inline std::string SocketStream::get_remote_addr()
	{
		return detail::get_remote_addr(sock_);
	}
};