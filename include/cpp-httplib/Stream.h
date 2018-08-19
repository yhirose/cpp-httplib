#pragma once
#include <string>

namespace httplib {
	class Stream {
	public:
		virtual ~Stream() {}
		virtual int read(char* ptr, size_t size) = 0;
		virtual int write(const char* ptr, size_t size1) = 0;
		virtual int write(const char* ptr) = 0;
		virtual std::string get_remote_addr() = 0;

		template <typename ...Args>
		void write_format(const char* fmt, const Args& ...args);
	};

	template <typename ...Args>
	inline void Stream::write_format(const char* fmt, const Args& ...args)
	{
		const auto bufsiz = 2048;
		char buf[bufsiz];

#if defined(_MSC_VER) && _MSC_VER < 1900
		auto n = _snprintf_s(buf, bufsiz, bufsiz - 1, fmt, args...);
#else
		auto n = snprintf(buf, bufsiz - 1, fmt, args...);
#endif
		if (n > 0) {
			if (n >= bufsiz - 1) {
				std::vector<char> glowable_buf(bufsiz);

				while (n >= static_cast<int>(glowable_buf.size() - 1)) {
					glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
					n = _snprintf_s(&glowable_buf[0], glowable_buf.size(), glowable_buf.size() - 1, fmt, args...);
#else
					n = snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...);
#endif
				}
				write(&glowable_buf[0], n);
			}
			else {
				write(buf, n);
			}
		}
	}
};