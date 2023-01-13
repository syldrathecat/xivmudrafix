#ifndef FORMAT_HPP
#define FORMAT_HPP

#include <cstdint>
#include <string>

std::string format_string(const char* fmt, ...)
#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)));
#endif

#endif // FORMAT_HPP
