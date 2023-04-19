#include "NtSyscaller.h"
#include "fnv1a.h"

#define NOMINMAX
#include <Windows.h>
#include <fstream>

#ifdef _WIN64
constexpr uint32_t SYSCALL_BYTE_SIZE = 21;
constexpr uint32_t SYSCALL_NUMBER_OFFSET = 4;
constexpr uint32_t SYSCALL_SIGNATURE = 0xB8D18B4C;
#else
constexpr uint32_t SYSCALL_BYTE_SIZE = 15;
constexpr uint32_t SYSCALL_NUMBER_OFFSET = 1;
constexpr uint8_t SYSCALL_SIGNATURE[] = { 0xB8, 0xBA, 0xFF, 0xD2, 0xC2 };
constexpr uint32_t SYSCALL_SIGNATURE_OFFSETS[] = { 0, 5, 10, 11, 12 };
constexpr uint32_t SYSCALL_WOW64_TRANSFER_OFFSET = 6;
#endif

NtSyscaller::NtSyscaller(): m_ntdll_image(nullptr), m_shellcode_buffer(nullptr) {
	m_ntdll_address = uintptr_t(GetModuleHandleA("ntdll.dll"));
	map_ntdll();

	m_syscall_info = find_syscalls();
	//print_syscalls(syscalls);

	allocate_syscalls();
}

NtSyscaller::~NtSyscaller() {
	VirtualFree(m_shellcode_buffer, 0, MEM_RELEASE);
	delete[] m_ntdll_image;
}

std::vector<NtSyscaller::SyscallInfo> NtSyscaller::find_syscalls() {
	std::vector<SyscallInfo> syscalls;

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)m_ntdll_image;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(m_ntdll_image + dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(m_ntdll_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD num_functions = std::min(export_dir->NumberOfNames, export_dir->NumberOfFunctions);
	uint32_t* function_addresses = (uint32_t*)(m_ntdll_image + export_dir->AddressOfFunctions);
	uint32_t* function_names = (uint32_t*)(m_ntdll_image + export_dir->AddressOfNames);
	uint16_t* function_ordinals = (uint16_t*)(m_ntdll_image + export_dir->AddressOfNameOrdinals);
	for (int i = 0; i < num_functions; i++) {
		const char* name = (const char*)(m_ntdll_image + function_names[i]);
		uintptr_t address = uintptr_t(m_ntdll_image + function_addresses[function_ordinals[i]]);

		bool is_syscall = false;
#ifdef _WIN64
		// Check if it is a syscall by seeing if function starts with a certain set of bytes
		if (*(uint32_t*)address == SYSCALL_SIGNATURE) {
			is_syscall = true;
		}
#else
		// Check if it is a syscall by seeing if function matches with our signature
		is_syscall = true;
		for (int j = 0; j < sizeof(SYSCALL_SIGNATURE); j++) {
			if (*(uint8_t*)(address + SYSCALL_SIGNATURE_OFFSETS[j]) != SYSCALL_SIGNATURE[j]) {
				is_syscall = false;
				break;
			}
		}
#endif
		if (is_syscall) {
			SyscallInfo info;
			info.name = name;
			info.hash = FNV1A_RUNTIME(name);
			info.rva = address - uintptr_t(m_ntdll_image);
			info.number = *(uint32_t*)(address + SYSCALL_NUMBER_OFFSET);

			syscalls.push_back(info);
		}

	}

	return syscalls;
}

void NtSyscaller::print_syscalls() {
	for (auto& s : m_syscall_info) {
		printf("%s (rva %X) - %i\n", s.name.c_str(), s.rva, s.number);
	}
}

void NtSyscaller::allocate_syscalls() {
	if (m_syscall_info.empty()) {
		return;
	}

	m_shellcode_buffer = (uint8_t*)VirtualAlloc(nullptr, SYSCALL_BYTE_SIZE * m_syscall_info.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!m_shellcode_buffer) {
		throw std::runtime_error("Failed to allocate buffer for syscall shellcode");
	}
	
#ifndef _WIN64
	uint32_t segment_transfer = *(uint32_t*)(m_ntdll_address + m_syscall_info[0].rva + SYSCALL_WOW64_TRANSFER_OFFSET);
#endif

	for (int i = 0; i < m_syscall_info.size(); i++) {
		uint8_t* cur_pos = m_shellcode_buffer + i * SYSCALL_BYTE_SIZE;
		memcpy(cur_pos, m_ntdll_image + m_syscall_info[i].rva, SYSCALL_BYTE_SIZE);
		m_syscalls[FNV1A_RUNTIME(m_syscall_info[i].name.c_str())] = uintptr_t(cur_pos);

#ifndef _WIN64
		* (uint32_t*)(cur_pos + SYSCALL_WOW64_TRANSFER_OFFSET) = segment_transfer;
#endif
	}
}

void NtSyscaller::map_ntdll() {
	// Load the ntdll.dll file into memory
	CHAR path[MAX_PATH];
	GetModuleFileNameA(HMODULE(m_ntdll_address), path, MAX_PATH);

	std::ifstream file(path, std::ios::in | std::ios::binary);
	file.seekg(0, std::ios::end);
	size_t file_size = file.tellg();
	file.seekg(0, std::ios::beg);

	uint8_t* file_buffer = new uint8_t[file_size];
	if (!file_buffer) {
		throw std::runtime_error("Failed to allocate buffer for ntdll file");
	}
	file.read((char*)file_buffer, file_size);

	// Map the "fresh" ntdll into memory 
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		throw std::runtime_error("Invalid DOS header for ntdll");
	}

	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(file_buffer + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		throw std::runtime_error("Invalid NT headers for ntdll");
	}

	// allocate memory to map the actual binary image into
	m_ntdll_image = new uint8_t[nt_headers->OptionalHeader.SizeOfImage];
	if (!m_ntdll_image) {
		throw std::runtime_error("Failed to allocate memory for ntdll image");
	}
	
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(uintptr_t(nt_headers) + sizeof(IMAGE_NT_HEADERS));

	// Map the headers and sections
	memcpy(m_ntdll_image, file_buffer, nt_headers->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		memcpy(m_ntdll_image + section_header[i].VirtualAddress, file_buffer + section_header[i].PointerToRawData, section_header[i].SizeOfRawData);
	}

	// cleanup
	delete[] file_buffer;
}