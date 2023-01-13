#include "format.hpp"

#include <cstdarg>
#include <cstdio>
#include <stdexcept>

std::string format_string(const char* fmt, ...)
{
	char buf[32];
	char* pbuf = buf;

	va_list ap;
	va_start(ap, fmt);

	auto fn = [fmt, &ap](char* buf_, std::size_t bufsz)
	{
		va_list ap2;
		va_copy(ap2, ap);
		auto result = std::vsnprintf(buf_, bufsz, fmt, ap2);
		va_end(ap2);
		return result;
	};

	int nbytes = fn(pbuf, sizeof buf);

	if (nbytes < 0)
	{
		va_end(ap);
		throw std::logic_error("snprintf failed");
	}

	if (std::size_t(nbytes) > sizeof buf)
	{
		pbuf = new char[std::size_t(nbytes)];
		fn(pbuf, std::size_t(nbytes));
	}

	if (nbytes < 0)
	{
		if (pbuf != buf)
			delete[] pbuf;

		va_end(ap);
		throw std::logic_error("snprintf failed");
	}

	std::string result(pbuf, std::size_t(nbytes));

	if (pbuf != buf)
		delete[] pbuf;

	va_end(ap);
	return result;
}
