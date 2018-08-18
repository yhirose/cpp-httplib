#pragma once
#include "detail.h"
#include "httplib_typedefs.h"
#include <string>
#include <map>
#include <regex>
#include <functional>

struct MultipartFile;

namespace httplib {
	struct Request {

		std::string    version;
		std::string    method;
		std::string    target;
		std::string    path;
		Headers        headers;
		std::string    body;
		Params         params;
		MultipartFiles files;
		Match          matches;

		Progress       progress;

		bool has_header(const char* key) const;
		std::string get_header_value(const char* key) const;
		void set_header(const char* key, const char* val);

		bool has_param(const char* key) const;
		std::string get_param_value(const char* key) const;

		bool has_file(const char* key) const;
		MultipartFile get_file_value(const char* key) const;
	};

	inline bool Request::has_header(const char* key) const
	{
		return headers.find(key) != headers.end();
	}

	inline std::string Request::get_header_value(const char* key) const
	{
		return detail::get_header_value(headers, key, "");
	}

	inline void Request::set_header(const char* key, const char* val)
	{
		headers.emplace(key, val);
	}

	inline bool Request::has_param(const char* key) const
	{
		return params.find(key) != params.end();
	}

	inline std::string Request::get_param_value(const char* key) const
	{
		auto it = params.find(key);
		if (it != params.end()) {
			return it->second;
		}
		return std::string();
	}

	inline bool Request::has_file(const char* key) const
	{
		return files.find(key) != files.end();
	}

	inline MultipartFile Request::get_file_value(const char* key) const
	{
		auto it = files.find(key);
		if (it != files.end()) {
			return it->second;
		}
		return MultipartFile();
	}
};