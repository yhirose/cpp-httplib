#pragma once

#ifdef CPPHTTPLIB_IOCP_SUPPORT

#include "detail.h"
#include "Stream.h"
#include "iocp_types.h"
#include <string>
#include <WinSock2.h>

namespace httplib {

	namespace detail {
		std::string get_remote_addr(socket_t sock);
	};

	class IOCPStream : public Stream {
	public:
		IOCPStream(PPER_SOCKET_CONTEXT _lpPerSocketContext, PPER_IO_CONTEXT _lpIOContext,
			DWORD& _dwSendNumBytes, DWORD& _dwFlags);
		virtual ~IOCPStream();

		virtual int read(char* ptr, size_t size);
		virtual int write(const char* ptr, size_t size);
		virtual int write(const char* ptr);
		virtual std::string get_remote_addr();
		PPER_SOCKET_CONTEXT getLpPerSocketContext()
		{
			return lpPerSocketContext;
		}

	private:
		PPER_SOCKET_CONTEXT lpPerSocketContext;
		PPER_IO_CONTEXT lpIOContext;
		DWORD& dwSendNumBytes;
		DWORD& dwFlags;
		int strm_index = 0;
	};

	IOCPStream::IOCPStream(PPER_SOCKET_CONTEXT _lpPerSocketContext, PPER_IO_CONTEXT _lpIOContext,
		DWORD& _dwSendNumBytes, DWORD& _dwFlags) :
		lpPerSocketContext(_lpPerSocketContext), lpIOContext(_lpIOContext),
		dwSendNumBytes(_dwSendNumBytes), dwFlags(_dwFlags)
	{}

	IOCPStream::~IOCPStream() {}

	inline int IOCPStream::read(char* ptr, size_t size)
	{
		int start_i = strm_index;
		for (; strm_index < (size + start_i) && strm_index < lpIOContext->wsabuf.len; ++strm_index)
		{
			ptr[strm_index - start_i] = lpIOContext->wsabuf.buf[strm_index];
		}
		return strm_index - start_i;
	}

	inline int IOCPStream::write(const char* ptr, size_t size)
	{
		lpIOContext->wsabuf.buf = (char*)ptr;
		lpIOContext->wsabuf.len = size;

		int nRet = WSASend(
			lpPerSocketContext->Socket,
			&lpIOContext->wsabuf, 1, &dwSendNumBytes,
			dwFlags,
			&(lpIOContext->Overlapped), NULL);
		if (nRet == SOCKET_ERROR)
		{
			return nRet;
		}
		return nRet;
	}

	inline int IOCPStream::write(const char* ptr)
	{
		return write(ptr, strlen(ptr));
	}

	inline std::string IOCPStream::get_remote_addr()
	{
		return detail::get_remote_addr(lpPerSocketContext->Socket);
	}
};

#endif