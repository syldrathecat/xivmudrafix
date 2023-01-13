#ifndef MEMORY_HPP
#define MEMORY_HPP

#include <any>
#include <cstdint>
#include <filesystem>
#include <list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

class process_error : public std::runtime_error
{
	public:
		using std::runtime_error::runtime_error;
};

class mem_error : public std::runtime_error
{
	public:
		using std::runtime_error::runtime_error;
};

class peek_error : public mem_error
{
	public:
		using mem_error::mem_error;
};

class poke_error : public mem_error
{
	public:
		using mem_error::mem_error;
};

struct MemOffset
{
	static constexpr int invalid_offset = -2147483648;
	std::basic_string<int> offsets;

	MemOffset(int offset);
	MemOffset(std::string_view str);
	~MemOffset();
};

class MemHandle
{
	public:
		enum mode_t
		{
			Peek,
			Poke
		};

	private:
		struct impl_t;
		std::unique_ptr<impl_t> impl;

	public:
		MemHandle(std::any handle, mode_t mode);
		MemHandle(MemHandle&&) = default;
		~MemHandle();

		void read(std::size_t offset, void* buf, std::size_t count);
		void write(std::size_t offset, const void* buf, std::size_t count);

		int read8(std::size_t offset);
		int read16(std::size_t offset);
		std::uint32_t read32(std::size_t offset);
		std::uint64_t read64(std::size_t offset);
};

struct MemRegion
{
	enum {
		R = 0x01,
		W = 0x02,
		X = 0x04
	};

	std::size_t start;
	std::size_t end;
	int flags;

	bool shared;
	bool mapped;
	std::string filename;

	bool readable() const { return flags & R; }
	bool writeable() const { return flags & W; }
	bool executable() const { return flags & X; }
};

class Process
{
	public:

	private:
		struct impl_t;
		std::unique_ptr<impl_t> impl;

	public:
		MemRegion text{};
		MemRegion data{};
		MemRegion rdata{};

		Process(const std::string& name);
		Process(Process&&) = default;
		~Process();

		std::list<MemRegion> regions();
		MemHandle open_mem(MemHandle::mode_t);
};

enum mem_search_mode_t {
	Search_any,

	Search_R,
	Search_W,
	Search_X,
	Search_RW,
	Search_RX,
	Search_WX,
	Search_RWX,

	Search_R_only,
	Search_W_only,
	Search_X_only,
	Search_RW_only,
	Search_RX_only,
	Search_WX_only,

	Search_text,
	Search_rdata,
	Search_data
};

std::list<std::size_t> mem_find_sig(Process& proc, MemHandle& mh, std::string_view sig, mem_search_mode_t mode = Search_any);

std::size_t mem_resolve_offset(MemHandle& mh, std::size_t base, const MemOffset& offset);

#endif // MEMORY_HPP
