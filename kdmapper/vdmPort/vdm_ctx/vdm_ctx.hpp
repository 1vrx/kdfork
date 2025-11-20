#pragma once
#include <windows.h>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
//#include "../vdm/vdm.hpp"
#include "../util/util.hpp" // include util directly, avoid including vdm.hpp to prevent circular include

namespace vdm
{
	// change this to whatever you want :^)
	constexpr std::pair<const char*, const char*> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };
	inline std::atomic<bool> is_page_found = false;
	inline std::atomic<void*> syscall_address = nullptr;
	inline std::uint16_t nt_page_offset;
	inline std::uint32_t nt_rva;
	inline std::uint8_t* ntoskrnl;

	// Forward-declare the low-level physical read/write functions to avoid circular include problems.
	// Signatures must match kdmapper\vdmPort\vdm\vdm.hpp definitions.
	auto read_phys(void* addr, void* buffer, std::size_t size) -> bool;
	auto write_phys(void* addr, void* buffer, std::size_t size) -> bool;

	// Use concrete function signatures for std::function aliases (avoid decltype on potentially incomplete symbol)
	using read_phys_t = std::function<bool(void*, void*, std::size_t)>;
	using write_phys_t = std::function<bool(void*, void*, std::size_t)>;

	// namespace-scoped function-based replacement for the old vdm_ctx class
	extern read_phys_t phys_read;
	extern write_phys_t phys_write;

	// initialize the context (replaces constructor)
	void init(read_phys_t& read_func, write_phys_t& write_func);

	// replace setters
	void set_read(read_phys_t& read_func);
	void set_write(write_phys_t& write_func);

	// kernel memory read/write helpers (non-template)
	void rkm(void* dst, void* src, std::size_t size);
	void wkm(void* dst, void* src, std::size_t size);

	// typed helpers (templates must be in header)
	template <class T>
	__forceinline auto rkm(std::uintptr_t addr) -> T
	{
		T buffer;
		rkm((void*)&buffer, (void*)addr, sizeof(T));
		return buffer;
	}

	template <class T>
	__forceinline void wkm(std::uintptr_t addr, const T& value)
	{
		wkm((void*)addr, (void*)&value, sizeof(T));
	}

	// generic syscall trampoline: temporarily overwrite kernel syscall target to jump to 'addr'
	template <class T, class ... Ts>
	__forceinline std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args)
	{
		static const auto proc =
			GetProcAddress(
				LoadLibraryA(syscall_hook.second),
				syscall_hook.first
			);

		static std::mutex syscall_mutex;
		syscall_mutex.lock();

		// jmp [rip+0x0]
		std::uint8_t jmp_code[] =
		{
			0xff, 0x25, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00
		};

		std::uint8_t orig_bytes[sizeof jmp_code];
		*reinterpret_cast<void**>(jmp_code + 6) = addr;
		read_phys(vdm::syscall_address.load(), orig_bytes, sizeof orig_bytes);

		// execute hook...
		write_phys(vdm::syscall_address.load(), jmp_code, sizeof jmp_code);	

		if constexpr (std::is_void_v<std::invoke_result_t<T, Ts...>>) {
			reinterpret_cast<T>(proc)(args ...); // call, ignore result
			write_phys(vdm::syscall_address.load(), orig_bytes, sizeof orig_bytes);
			syscall_mutex.unlock();
			return;
		}
		else {
			auto result = reinterpret_cast<T>(proc)(args ...);
			write_phys(vdm::syscall_address.load(), orig_bytes, sizeof orig_bytes);
			syscall_mutex.unlock();
			return result;
		}
	}

	// helper to obtain a PEPROCESS for a PID (uses syscall template)
	__forceinline auto get_peprocess(std::uint32_t pid) -> PEPROCESS
	{
		static const auto ps_lookup_peproc =
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"PsLookupProcessByProcessId");

		PEPROCESS peproc = nullptr;
		syscall<PsLookupProcessByProcessId>(
			ps_lookup_peproc,
			(HANDLE)pid,
			&peproc
		);
		return peproc;
	}

	__forceinline auto read(void* addr, void* buffer, size_t size) -> bool
	{
		static const auto memcpy_addr = util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		if (!memcpy_addr) return false; // Safety check

		// Note: This is still dangerous if 'addr' is invalid!
		syscall<decltype(&memcpy)>(memcpy_addr, buffer, addr, size);

		return true;
	}

	__forceinline auto write(void* addr, void* buffer, size_t size) -> bool
	{
		static const auto memcpy_addr = util::get_kmodule_export("ntoskrnl.exe", "memcpy");

		if (!memcpy_addr) return false; // Safety check

		// Note: This is still dangerous if 'addr' is invalid!
		syscall<decltype(&memcpy)>(memcpy_addr, addr, buffer, size);

		return true;
	}

	using tMmGetPhysicalAddress = uint64_t(*)(void*);

	__forceinline auto get_physical_address(void* virtual_address) -> uint64_t
	{
		static const auto mm_get_phys_addr =
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"MmGetPhysicalAddress");

		// Check if export was found to prevent crashing
		if (!mm_get_phys_addr) return 0;

		// MmGetPhysicalAddress takes 1 arg: BaseAddress
		auto phys_addr = syscall<tMmGetPhysicalAddress>(
			mm_get_phys_addr,
			virtual_address
		);

		return phys_addr;
	}


	typedef enum _MEMORY_CACHING_TYPE {
		MmNonCached = 0,
		MmCached = 1,
		MmWriteCombined = 2,
		MmHardwareCoherentCached = 3,
		MmNonCachedUnordered = 4,
		MmUSWCCached = 5,
		MmMaximumCacheType = 6,
		MmNotMapped = -1
	} MEMORY_CACHING_TYPE;

	using tMmMapIoSpace = void* (*)(uint64_t, size_t, MEMORY_CACHING_TYPE);
	using tMmUnmapIoSpace = void(*)(void*, size_t);

	__forceinline auto map_io_space(uint64_t physical_address, size_t size) -> void*
	{
		static const auto mm_map_ptr =
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"MmMapIoSpace");

		if (!mm_map_ptr) return nullptr;

		return syscall<tMmMapIoSpace>(
			mm_map_ptr,
			physical_address,
			size,
			MmNonCached
		);
	}

	__forceinline auto unmap_io_space(void* base_address, size_t size) -> void
	{
		static const auto mm_unmap_ptr =
			util::get_kmodule_export(
				"ntoskrnl.exe",
				"MmUnmapIoSpace");

		if (!mm_unmap_ptr) return;

		syscall<tMmUnmapIoSpace>(
			mm_unmap_ptr,
			base_address,
			size
		);
	}

}