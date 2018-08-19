#pragma once
#include "detail.h"
#include "httplib_typedefs.h"
#include <functional>
#include <string>
#include <map>

namespace httplib {
	struct Response {

		std::string version;
		int         status;
		Headers     headers;
		std::string body;
		std::function<std::string(uint64_t offset)> streamcb;

		bool has_header(const char* key) const;
		std::string get_header_value(const char* key) const;
		void set_header(const char* key, const char* val);

		void set_redirect(const char* uri);
		void set_content(const char* s, size_t n, const char* content_type);
		void set_content(const std::string& s, const char* content_type);

		Response() : status(-1) {}
	};

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
};