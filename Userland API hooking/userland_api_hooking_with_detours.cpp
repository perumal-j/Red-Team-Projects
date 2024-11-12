#include <windows.h>
#include "detours.h"

//original function pointer
int (WINAPI *OriginalMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = MessageBoxA;

//Hook Function
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    //Modify Message Text
    return OriginalMessageBoxA(hWnd, "Hooked Message", lpCaption, uType);
}

int main() {
    // Attach the Hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalMessageBoxA,HookedMessageBoxA);
    DetourTransactionCommit();

    // Call the hooked function
    MessageBoxA(NULL, "Original Message", "Hook Test", MB_OK);

    //Detach hook
    DetourTransactionBegin();
    DetourUpdateThread(DetourCurrentThread());
    DetourDetach(&(PVOID&)OriginalMessageBoxA,HookedMessageBoxA);
    DetourTransactionCommit();

    return 0;
}