#pragma once
#include "Stream.h"
#include <assert.h>

// NOTE: until the read size reaches `fixed_buffer_size`, use `fixed_buffer`
// to store data. The call can set memory on stack for performance.

namespace httplib {
	namespace detail {
		class stream_line_reader {
		public:
			stream_line_reader(Stream& strm, char* fixed_buffer, size_t fixed_buffer_size)
				: strm_(strm)
				, fixed_buffer_(fixed_buffer)
				, fixed_buffer_size_(fixed_buffer_size) {
			}

			const char* ptr() const {
				if (glowable_buffer_.empty()) {
					return fixed_buffer_;
				}
				else {
					return glowable_buffer_.data();
				}
			}

			bool getline() {
				fixed_buffer_used_size_ = 0;
				glowable_buffer_.clear();

				for (size_t i = 0; ; i++) {
					char byte;
					auto n = strm_.read(&byte, 1);

					if (n < 0) {
						return false;
					}
					else if (n == 0) {
						if (i == 0) {
							return false;
						}
						else {
							break;
						}
					}

					append(byte);

					if (byte == '\n') {
						break;
					}
				}

				return true;
			}

		private:
			void append(char c) {
				if (fixed_buffer_used_size_ < fixed_buffer_size_ - 1) {
					fixed_buffer_[fixed_buffer_used_size_++] = c;
					fixed_buffer_[fixed_buffer_used_size_] = '\0';
				}
				else {
					if (glowable_buffer_.empty()) {
						assert(fixed_buffer_[fixed_buffer_used_size_] == '\0');
						glowable_buffer_.assign(fixed_buffer_, fixed_buffer_used_size_);
					}
					glowable_buffer_ += c;
				}
			}

			Stream& strm_;
			char* fixed_buffer_;
			const size_t fixed_buffer_size_;
			size_t fixed_buffer_used_size_;
			std::string glowable_buffer_;
		};
	};
};