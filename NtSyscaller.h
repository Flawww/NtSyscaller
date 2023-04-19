#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>

class NtSyscaller {
public:
	NtSyscaller();
	~NtSyscaller();

	template<typename ... targs>
	int syscall(uint32_t syscall_hash, targs ... args) {
		uintptr_t fn = m_syscalls[syscall_hash];
		if (!fn) {
			throw std::runtime_error("Invalid syscall, syscall number not found");
		}

#ifdef _WIN64
		using fn_type = int(__cdecl*)(targs...);
#else
		using fn_type = int(__stdcall*)(targs...);
#endif
		return ((fn_type)fn)(args...);
	}

private:
	struct SyscallInfo {
		std::string name;
		uintptr_t rva;
		uint32_t hash;
		int32_t number;
	};

	std::vector<SyscallInfo> find_syscalls();
	void print_syscalls();
	void allocate_syscalls();

	void map_ntdll(); // maps ntdll from disk into a buffer to ensure its unmodified.

	uintptr_t m_ntdll_address;
	uint8_t* m_ntdll_image; // Contains a copy of ntdll from disk
	uint8_t* m_shellcode_buffer;
	std::vector<SyscallInfo> m_syscall_info;
	std::unordered_map<uint32_t, uintptr_t> m_syscalls;
};