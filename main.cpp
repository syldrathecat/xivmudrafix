#include "memory.hpp"

#include <stdio.h>

#define PROC_NAME "ffxiv_dx11.exe"

int main(int argc, char** argv)
{
	Process proc(PROC_NAME);
	MemHandle peek_handle = proc.open_mem(MemHandle::Peek);
	MemHandle poke_handle = proc.open_mem(MemHandle::Poke);

	// Thanks to: https://github.com/UnknownX7/NoClippy/commit/8acee774ea9e15412c8376eee6cc0e302297971f
	auto results = mem_find_sig(proc, peek_handle, "F6 47 3B 02 ?? 3E 8D 83 83 C1 FF FF", Search_text);

	if (results.empty()) {
		fprintf(stderr, "Failed to find memory signature\n");
		return 1;
	}

	for (auto result : results) {
		unsigned char c = 0x00;
		peek_handle.read(result + 4, &c, 1);

		if (c == 0x75) {
			fprintf(stderr, "Patch is already appied\n");
			return 1;
		} else if (c != 0x74) {
			continue;
		}

		poke_handle.write(result + 4, "\x75", 1);
	}

	printf("Mudra fix applied!");
}
