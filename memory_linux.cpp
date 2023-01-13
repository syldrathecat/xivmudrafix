#include "memory.hpp"

#include "format.hpp"

// for open, lseek, read, write, close
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

static const fs::path proc_path("/proc");

static int find_pid_by_name(std::string_view name)
{
	int result = 0;

	for (auto& entry : fs::directory_iterator(proc_path))
	{
		if (!entry.is_directory())
			continue;

		auto&& pid_path = entry.path();

		int pid = std::atoi(pid_path.filename().c_str());

		if (pid > 0)
		{
			std::string line;
			auto status_path = pid_path / "status";
			std::ifstream f(status_path);

			if (!std::getline(f, line))
				continue;

			if (line.compare(0, 5, "Name:") != 0)
				 continue;

			std::size_t idx = line.find_first_of(" \t");

			if (idx == std::string::npos)
				continue;

			idx = line.find_first_not_of(" \t", idx);

			if (idx == std::string::npos)
				continue;

			if (line.compare(idx, name.size(), name) == 0)
			{
				if (!result)
					result = pid;

				if (name.size() == line.size() - idx)
					return pid;
			}
		}
	}

	return result;
}

struct MemHandle::impl_t
{
	int fd;
};

MemHandle::MemHandle(std::any handle, mode_t mode)
	: impl(std::make_unique<impl_t>())
{
	int flags = 0;

	if (mode == Peek)
		flags = O_RDONLY;
	else if (mode == Poke)
		flags = O_RDWR;

	auto memfile = std::any_cast<std::filesystem::path>(handle);

	impl->fd = open(memfile.c_str(), flags);

	if (impl->fd < 0)
	{
		std::string msg = "Failed to open memory for ";

		if (mode == Peek)
			msg += "reading";
		else if (mode == Poke)
			msg += "writing";

		msg += " (";
		msg += memfile;
		msg += ": ";
		msg += std::strerror(errno);
		msg += ").";

		throw mem_error(msg);
	}
}

MemHandle::~MemHandle()
{
	close(impl->fd);
}

void MemHandle::read(std::size_t offset, void* buf, std::size_t count)
{
	off_t offset_signed = off_t(offset);

	// Unsure if signed offsets actually work correctly
	//if (offset_signed < 0)
	//	throw std::logic_error("offset too large");

	errno = 0;

	{
		off_t result = lseek(impl->fd, offset_signed, SEEK_SET);

		if (result < 0 && errno != 0)
		{
			std::string msg = "Failed to seek to process memory at offset 0x";

			msg += format_string("%zX", offset);
			msg += ": ";
			msg += strerror(errno);

			throw peek_error(msg);
		}
	}

	{
		ssize_t result = ::read(impl->fd, buf, count);

		if (result < 0)
		{
			std::string msg = "Failed to read process memory at offset 0x";

			msg += format_string("%zX", offset);
			msg += ": ";
			msg += strerror(errno);

			throw peek_error(msg);
		}
	}
}

void MemHandle::write(std::size_t offset, const void* buf, std::size_t count)
{
	off_t offset_signed = off_t(offset);

	// Unsure if signed offsets actually work correctly
	//if (offset_signed < 0)
	//	throw std::logic_error("offset too large");

	errno = 0;

	{
		off_t result = lseek(impl->fd, offset_signed, SEEK_SET);

		if (result < 0 && errno != 0)
		{
			std::string msg = "Failed to seek to process memory at offset 0x";

			msg += format_string("%zX", offset);
			msg += ": ";
			msg += strerror(errno);

			throw peek_error(msg);
		}
	}

	{
		ssize_t result = ::write(impl->fd, buf, count);

		if (result < 0)
		{
			std::string msg = "Failed to write process memory at offset 0x";

			msg += format_string("%zX", offset);
			msg += ": ";
			msg += strerror(errno);

			throw peek_error(msg);
		}
	}
}

struct Process::impl_t
{
	std::string name;
	int pid = 0;
	std::filesystem::path memfile;

	impl_t(std::string name)
		: name(std::move(name))
	{ }
};

Process::Process(const std::string& name)
	: impl(std::make_unique<impl_t>(std::move(name)))
{
	impl->pid = find_pid_by_name(impl->name);

	if (impl->pid == 0)
	{
		std::string msg = "Failed to find process: ";
		throw process_error(msg + impl->name);
	}

	impl->memfile = proc_path / format_string("%d", impl->pid) / "mem";

	int state = 0;

	// Assume first 3 sections are {text,rdata,data}
	for (auto&& region : regions())
	{
		if (state == 0)
		{
			if (region.mapped && region.filename.compare(0, impl->name.size(), impl->name) == 0)
				++state;
		}
		else if (state == 1)
		{
			if (region.readable() && region.executable())
				text = region;
			++state;
		}
		else if (state == 2)
		{
			if (region.readable())
				rdata = region;
			++state;
		}
		else if (state == 3)
		{
			if (region.readable() && region.writeable())
				data = region;
			break;
		}
	}

	if (text.start == 0)
		throw process_error("Could not locate .text section in memory");

	// Whomst cares
	//if (m_rdata.start == 0)
	//	throw process_error("Could not locate .rdata section");

	if (data.start == 0)
		throw process_error("Could not locate .data section in memory");
}

Process::~Process()
{ }

std::list<MemRegion> Process::regions()
{
	auto maps_path = proc_path / format_string("%d", impl->pid) / "maps";
	std::list<MemRegion> regions;
	std::string line;
	std::ifstream f(maps_path);

	while (std::getline(f, line))
	{
		std::size_t start, end;
		char r, w, x, s;
		int devmaj, devmin;
		std::size_t procname_offset = 0;

		std::sscanf(line.c_str(), "%zx-%zx %c%c%c%c %*x %x:%x %*d%*[ ]%zn",
			&start, &end, &r, &w, &x, &s, &devmaj, &devmin, &procname_offset
		);

		// I think WINE maps exclusively native data in to this region
		if (start >= 0x7f0000000000)
			continue;

		// Can't even lseek to addresses this large?
		if (start >= 0x7f00000000000000)
			continue;

		MemRegion region{};

		region.start = start;
		region.end = end;

		if (r == 'r') region.flags |= MemRegion::R;
		if (w == 'w') region.flags |= MemRegion::W;
		if (x == 'x') region.flags |= MemRegion::X;

		if (s == 's')
			region.shared = true;

		if (devmaj != 0 || devmin != 0)
		{
			region.mapped = true;
			region.filename = std::string(line.data() + procname_offset);

			// Skip special kernel sections like [vdso]
			// Skipping sections named [heap] is probably a bad idea...
			/*
			if (region.filename.compare(0, 1, "[") == 0)
				continue;
			*/

			// Skip special device memory
			if (region.filename.compare(0, 5, "/dev/") == 0)
				continue;

			if (region.filename.compare(0, 7, "/memfd:") == 0)
				continue;

			// Strip everything except the filename from the path
			std::size_t idx = region.filename.find_last_of('/');

			if (idx != std::string::npos)
				region.filename.erase(0, idx + 1);
		}

		regions.push_back(std::move(region));
	}

	return regions;
}

MemHandle Process::open_mem(MemHandle::mode_t mode)
{
	MemHandle handle(impl->memfile, mode);
	return handle;
}
