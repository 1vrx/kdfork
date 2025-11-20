#pragma once
#include <windows.h>
#include <cstdint>

#include "../util/util.hpp"
#include "../util/loadup.hpp"
#include "raw_driver.hpp"
#include "new_driver.h"
#include "../vdm_ctx/vdm_ctx.hpp"

#pragma pack(push, 1)
struct memory_request {
	HANDLE h_mem;
	size_t size;
	std::uint64_t phys_addr;
	void* p_mapped;
};
#pragma pack(pop)

namespace vdm
{
	inline HANDLE drv_handle;
	__forceinline auto load_drv() -> std::tuple<HANDLE, std::string, NTSTATUS>
	{
		std::printf("load_drv() called \n");

		const auto [result, key] =
			driver::load(
				vdm::raw_driver,
				sizeof(vdm::raw_driver)
			);

		if (result != STATUS_SUCCESS)
			return { {}, {}, result };

		drv_handle = CreateFile(
			"\\\\.\\inpoutx64",
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		return { vdm::drv_handle, key, result };
	}

	__forceinline auto unload_drv(HANDLE drv_handle, std::string drv_key) -> NTSTATUS
	{
		if (!CloseHandle(drv_handle))
			return STATUS_FAIL_CHECK;

		return driver::unload(drv_key);
	}


	__forceinline auto send_cmd(uint32_t ioctl_code, void* input_buffer, uint32_t input_size,
		void* output_buffer, uint32_t output_size) -> bool
	{
		if (vdm::drv_handle == INVALID_HANDLE_VALUE) {
			std::printf("Unable to find driver %ul", GetLastError());
			return false;
		}

		DWORD bytes_returned = 0;
		return DeviceIoControl(
			vdm::drv_handle,
			ioctl_code,
			input_buffer, input_size,
			output_buffer, output_size,
			&bytes_returned,
			nullptr
		) != 0;
	}

	__forceinline auto mapMem(void* addr, size_t size) -> void*
	{
		memory_request mr;
		mr.phys_addr = reinterpret_cast<uintptr_t>(addr);
		mr.size = size; //casting a size_t to a size_t...

		if (!send_cmd(0x9C40201C, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return nullptr;
		}

		return mr.p_mapped;


	}

	__forceinline auto unmapMem(void* pmapped, HANDLE hSec) -> bool
	{
		// create a properly-initialized memory_request to unmap
		memory_request mr;
		mr.p_mapped = pmapped;
		mr.h_mem = hSec;
		mr.size = 0;
		mr.phys_addr = 0;

		if (!send_cmd(0x9C402020, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return false;
		}

		return true;
	}


	__forceinline auto read_phys(void* addr, void* buffer, std::size_t size) -> bool
	{
		memory_request mr;
		mr.phys_addr = reinterpret_cast<uintptr_t>(addr);
		mr.size = size; //casting a size_t to a size_t...

		if (!send_cmd(0x9C40201C, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return false;
		}


		bool status = 0;

		__try
		{
			memcpy(buffer, mr.p_mapped, size);
			status = true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		if (!send_cmd(0x9C402020, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return false;
		}

		return status;

	}

	__forceinline auto write_phys(void* addr, void* buffer, std::size_t size) -> bool
	{
		memory_request mr;
		mr.phys_addr = reinterpret_cast<uintptr_t>(addr);
		mr.size = size; //casting a size_t to a size_t...

		if (!send_cmd(0x9C40201C, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return false;
		}


		bool status = 0;

		__try
		{
			memcpy(mr.p_mapped, buffer, size);
			status = true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		if (!send_cmd(0x9C402020, &mr, sizeof(mr), &mr, sizeof(mr))) {
			return false;
		}

		return status;

	}

}