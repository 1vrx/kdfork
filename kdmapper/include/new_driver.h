#pragma once
#include <Windows.h>
#include <string>
#include <iostream>


#include "utils.hpp"
#include "nt.hpp"

#include "../vdmPort/vdm_ctx/vdm_ctx.hpp"

namespace new_driver
{
	//constexpr ULONG32 ioctl1 = 0x80862007;
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;

	bool ClearPiDDBCacheTable();
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	bool AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList();
	bool ClearWdFilterDriverList();

	bool IsRunning();
	bool Load();
	bool Unload();

	//bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);
	//bool SetMemory(uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(uint64_t address, uint32_t size);
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, size_t size);
	/*added by herooyyy*/
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);

	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);

	bool FreePool(uint64_t address);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers();
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();


	
	//we have this "call kernel function" here, but we are going to use our syscall from vdm
	template<typename Ret, typename ...Args>
	bool CallKernelFunction(Ret* out_result, uint64_t kernel_function_address, const Args ...arguments) {
		constexpr auto call_void = std::is_same_v<Ret, void>;

		// if count of arguments is >4 fail
		static_assert(sizeof...(Args) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Build function pointer type: Ret(__cdecl *)(Args...)
		using func_t = Ret(*)(Args...);

		// call via vdm syscall trampoline
		if constexpr (std::is_void_v<Ret>) {
			// invoke and ignore result
			vdm::syscall<func_t>(reinterpret_cast<void*>(kernel_function_address), arguments...);
			return true;
		}
		else {
			Ret result = vdm::syscall<func_t>(reinterpret_cast<void*>(kernel_function_address), arguments...);
			*out_result = result;
			return true;
		}
	}
}
