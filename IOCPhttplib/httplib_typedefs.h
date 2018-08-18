#pragma once
#include <functional>
#include <regex>
#include <map>

#ifdef _WIN32
#include <WinSock2.h>
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

namespace httplib {

	namespace detail {
		struct ci;
	}

	enum class HttpVersion { v1_0 = 0, v1_1 };

	typedef std::multimap<std::string, std::string, detail::ci>  Headers;

	typedef std::multimap<std::string, std::string>                Params;
	typedef std::smatch                                            Match;
	typedef std::function<bool(uint64_t current, uint64_t total)> Progress;

	struct MultipartFile {
		std::string filename;
		std::string content_type;
		size_t offset = 0;
		size_t length = 0;
	};
	typedef std::multimap<std::string, MultipartFile> MultipartFiles;

#ifdef _WIN32
	typedef SOCKET socket_t;
#else
	typedef int socket_t;
#endif

	namespace detail {
		typedef std::multimap<std::string, std::string, ci>  Headers;

		typedef std::multimap<std::string, std::string>                Params;
		typedef std::smatch                                            Match;
		typedef std::function<bool(uint64_t current, uint64_t total)> Progress;

		typedef std::multimap<std::string, MultipartFile> MultipartFiles;

#ifdef _WIN32
		typedef SOCKET socket_t;
#else
		typedef int socket_t;
#endif
	};
};