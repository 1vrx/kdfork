#ifndef KDLIBMODE

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "new_driver.h"

#ifdef PDB_OFFSETS
#include "KDSymbolsHandler.h"
#endif

#include "vdmPort/vdm/vdm.hpp"
#include "vdmPort/vdm_ctx/vdm_ctx.hpp"


LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (vdm::drv_handle)
		new_driver::Unload();

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	Log("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: kdmapper.exe [--free | --indPages][--PassAllocationPtr][--copy-header]");

#ifdef PDB_OFFSETS
	Log(L"[--dontUpdateOffsets [--offsetsPath \"FilePath\"]]"); 
#endif
	
	Log(L" driver" << std::endl);

	PauseIfParentIsExplorer();
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	if (free) {
		Log(L"[+] Free pool memory after usage enabled" << std::endl);
	}

	if (indPagesMode) {
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (free && indPagesMode) {
		Log(L"[-] Can't use --free and --indPages at the same time" << std::endl);
		help();
		return -1;
	}

	if (passAllocationPtr) {
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		Log(L"[+] Copying driver header enabled" << std::endl);
	}

#ifdef PDB_OFFSETS
	bool UpdateOffset = !(paramExists(argc, argv, L"dontUpdateOffsets") > 0);
	int FilePathParamIdx = paramExists(argc, argv, L"offsetsPath");
	std::wstring offsetFilePath = utils::GetCurrentAppFolder() + L"\\offsets.ini";

	if (UpdateOffset && FilePathParamIdx > 0) {
		Log("[-] Can't set --offsetsPath without set --dontUpdateOffsets" << std::endl);
		help();
		return -1;
	}

	if (FilePathParamIdx > 0) {
		offsetFilePath = argv[FilePathParamIdx + 1];
		Log("[+] Setting Offsets File Path To: " << offsetFilePath << std::endl);
	}
#endif

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

#ifdef PDB_OFFSETS
	if (!KDSymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? utils::GetCurrentAppFolder() + L"\\" + SYM_FROM_PDB_EXE : L"")) {
		Log(L"[-] Error: Failed To Get Symbols Info." << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
#endif

	//add vdm setup here

	const auto [drv_handle, drv_key, load_status] = vdm::load_drv();
	if (drv_handle == INVALID_HANDLE_VALUE || load_status != STATUS_SUCCESS)
	{
		std::printf("[!] unable to load vulnerable driver... reason -> 0x%x\n", load_status);
		return -1;
	}

	std::printf("driver loaded \n");


	vdm::read_phys_t _read_phys =
		[&](void* addr, void* buffer, std::size_t size) -> bool
		{
			return vdm::read_phys(addr, buffer, size);
		};

	std::printf("initiated vdm::read_phys()\n");

	// write physical memory using the driver...
	vdm::write_phys_t _write_phys =
		[&](void* addr, void* buffer, std::size_t size) -> bool
		{
			return vdm::write_phys(addr, buffer, size);
		};

	std::printf("initiated vdm::write_phys()\n");

	vdm::init(_read_phys, _write_phys);

	std::printf("loaded vdm()\n");


	const auto ntoskrnl_base =
		reinterpret_cast<void*>(
			util::get_kmodule_base("ntoskrnl.exe"));

	std::printf("ntoskrnl.exe -> 0x%p\n", ntoskrnl_base);
	short mz_bytes = 0;
	vdm::read(ntoskrnl_base, &mz_bytes, sizeof(mz_bytes));

	/*
	if (!new_driver::Load()) {
		PauseIfParentIsExplorer();
		return -1;
	}
	*/
	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		vdm::unload_drv(drv_handle, drv_key);
		PauseIfParentIsExplorer();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	if (indPagesMode) {
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free, !copyHeader, mode, passAllocationPtr, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		vdm::unload_drv(drv_handle, drv_key);
		PauseIfParentIsExplorer();
		return -1;
	}

	if (!vdm::unload_drv(drv_handle, drv_key)) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
		PauseIfParentIsExplorer();
	}
	Log(L"[+] success" << std::endl);

}

#endif

