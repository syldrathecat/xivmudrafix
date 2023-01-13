#include "memory.hpp"

#include <algorithm>
#include <charconv>
#include <iostream>
#include <system_error>

static unsigned char hexdec(char nib)
{
	using uc = unsigned char;

	if (nib >= '0' && nib <= '9')
		return uc(nib) - '0';

	if (nib >= 'A' && nib <= 'F')
		return uc(nib) - 'A' + 10;

	if (nib >= 'a' && nib <= 'f')
		return uc(nib) - 'a' + 10;

	return 0;
}

struct decoded_sig_t
{
	std::basic_string<unsigned char> bytes;
	std::basic_string<unsigned char> mask;

	decoded_sig_t(std::string_view sig)
	{
		bytes.reserve((sig.size() + 2) / 3);
		mask.reserve((sig.size() + 2) / 3);

		std::size_t idx = sig.find_first_of(' ');

		while (!sig.empty())
		{
			std::string_view byte_str = sig.substr(0, idx);

			char c1 = '\0', c2 = '\0';

			if (byte_str.size() == 1)
			{
				c2 = byte_str[0];
			}
			else if (byte_str.size() == 2)
			{
				c1 = byte_str[0];
				c2 = byte_str[1];
			}

			if (c2 == '\0')
			{
				if (c1 == '?')
				{
					c2 = '?';
				}
				else
				{
					c2 = c1;
					c1 = '0';
				}
			}

			unsigned char byteval = 0x00;
			unsigned char maskval = 0xFF;

			if (c1 == '?')
				maskval &= 0x0F;
			else
				byteval |= hexdec(c1) << 4;

			if (c2 == '?')
				maskval &= 0xF0;
			else
				byteval |= hexdec(c2);

			bytes.push_back(byteval);
			mask.push_back(maskval);

			if (idx < sig.size() - 1)
				sig = sig.substr(idx + 1);
			else
				sig = {};
		}
	}

	std::size_t size() const
	{
		return bytes.size();
	}
};

MemOffset::MemOffset(int offset)
	: offsets{offset}
{ }

MemOffset::MemOffset(std::string_view str)
{
	std::size_t idx = str.find_first_of(',');

	offsets.reserve(unsigned(std::count(str.begin(), str.end(), ',')));

	while (!str.empty())
	{
		std::string_view byte_str = str.substr(0, idx);

		int offset = 0;

		{
			bool negative = false;
			const char* start = byte_str.data();
			const char* end = byte_str.data() + byte_str.size();

			if ((end - start) >= 1)
			{
				char c1 = start[0];

				if (c1 == '-')
				{
					negative = true;
					start += 1;
				}
			}

			if ((end - start) >= 2)
			{
				char c1 = start[0];
				char c2 = start[1];

				if (c1 == '0' && (c2 == 'x' || c2 == 'X'))
					start += 2;
			}

			auto result = std::from_chars(start, end, offset, 16);

			if (result.ec != std::errc{})
			{
				std::string msg = "Malformed offset string: '";
				msg += str;
				msg += "'\n";
				msg += std::make_error_code(result.ec).message();

				throw std::runtime_error(msg);
			}

			if (negative)
				offset = -offset;
		}

		offsets.push_back(offset);

		if (idx < str.size() - 1)
			str = str.substr(idx + 1);
		else
			str = {};
	}
}

MemOffset::~MemOffset()
{ }

int MemHandle::read8(std::size_t offset)
{
	std::uint8_t result;
	read(offset, &result, sizeof result);
	return result;
}

int MemHandle::read16(std::size_t offset)
{
	std::uint16_t result;
	read(offset, &result, sizeof result);
	return result;
}

std::uint32_t MemHandle::read32(std::size_t offset)
{
	std::uint32_t result;
	read(offset, &result, sizeof result);
	return result;
}

std::uint64_t MemHandle::read64(std::size_t offset)
{
	std::uint64_t result;
	read(offset, &result, sizeof result);
	return result;
}

std::list<std::size_t> mem_find_sig(Process& proc, MemHandle& mh, std::string_view sig, mem_search_mode_t mode)
{
	int any_flags = 0;
	int all_flags = 0;

	switch (int(mode))
	{
		case Search_R_only:
		case Search_RW_only:
		case Search_RX_only:
			all_flags |= MemRegion::R;
			[[fallthrough]];
		case Search_any:
		case Search_R:
		case Search_RW:
		case Search_RX:
		case Search_text:
		case Search_data:
		case Search_rdata:
			any_flags |= MemRegion::R;
			break;
	}

	switch (int(mode))
	{
		case Search_W_only:
		case Search_RW_only:
		case Search_WX_only:
			all_flags |= MemRegion::W;
			[[fallthrough]];
		case Search_any:
		case Search_W:
		case Search_RW:
		case Search_WX:
		case Search_data:
			any_flags |= MemRegion::W;
			break;
	}

	switch (int(mode))
	{
		case Search_X_only:
		case Search_RX_only:
		case Search_WX_only:
			all_flags |= MemRegion::X;
			[[fallthrough]];
		case Search_any:
		case Search_X:
		case Search_RX:
		case Search_WX:
		case Search_text:
			any_flags |= MemRegion::X;
			break;
	}

	std::list<std::size_t> addresses;
	std::size_t scanned = 0;

	decoded_sig_t decoded_sig(sig);

	unsigned char* sig_bytes = decoded_sig.bytes.data();
	unsigned char* sig_mask = decoded_sig.mask.data();
	auto sig_size = decoded_sig.size();

	if (sig_size >= 4096)
		throw std::logic_error("Signature cannot be longer than 4096 bytes");

	for (auto&& region : proc.regions())
	{
		bool any = any_flags == 0 || ((region.flags & any_flags) != 0);
		bool all = (region.flags & all_flags) == all_flags;

		if (mode == Search_text && region.start != proc.text.start)
			continue;

		if (mode == Search_data && region.start != proc.data.start)
			continue;

		if (mode == Search_rdata && region.start != proc.rdata.start)
			continue;

		if (any && all)
		{
			unsigned char buf[8192];
			std::size_t region_bytes = (region.end - region.start);
			scanned += region_bytes;

			std::size_t matched = 0;

			//std::cout << "scanning region " << format_string("%08zx", region.start) << '-' << format_string("%08zx", region.end)
			//          << " (" << (region.end - region.start) << " bytes)" << std::endl;

			// Haven't tested backtracking across pages entirely
			for (std::size_t addr = region.start; addr < region.end; addr += sizeof buf - sig_size)
			{
				std::size_t bytes = sizeof buf;

				bool first_page = (addr == region.start);

				// First sig_size bytes of buf are part of the previously scanned
				// page and should only be re-scanned during backtracking.
				// The first page of each region should be scanned entirely.
				std::size_t start_off = first_page ? 0 : sig_size;

				if (!first_page)
					bytes -= sig_size;

				if (bytes > region.end - addr)
					bytes = region.end - addr;

				try
				{
					mh.read(addr, buf + start_off, bytes);
				}
				catch (peek_error&)
				{
					// [vvar] region isn't readable by other processes
					continue;
				}

				for (std::size_t i = start_off; i < bytes; ++i)
				{
					unsigned char b = buf[i];

					if ((b & sig_mask[matched]) == sig_bytes[matched])
					{
						if (matched == sig_size - 1)
						{
							addresses.push_back(addr + i - start_off - matched);
							matched = 0;
						}
						else
						{
							++matched;
						}
					}
					else
					{
						i -= matched;
						matched = 0;
					}
				}
			}
		}
	}

	//std::cout << scanned << " bytes scanned." << std::endl;
	//std::cout << addresses.size() << " match(es)." << std::endl;

	return addresses;
}

std::size_t mem_resolve_offset(MemHandle& mh, std::size_t base, const MemOffset& offset)
{
	std::size_t i = 0;

	if (i < offset.offsets.size() && offset.offsets[i] != MemOffset::invalid_offset)
	{
		base = std::size_t(std::intmax_t(base) + offset.offsets[i]);
		++i;

		if (i < offset.offsets.size())
			base = std::size_t(mh.read64(base));
	}

	return base;
}
