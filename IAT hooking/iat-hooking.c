/*
EXP#1 IAT Hooking
Ref: C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin
Date: 12/07/18
*/
#include<stdio.h>
#include<windows.h>
#include<winternl.h>
/*typedef struct _PROCESS_BASIC_INFORMATION{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;*/
PROCESS_BASIC_INFORMATION *pbi;
int main()
{
    PULONG opt = 0;
    pbi = malloc(sizeof(*pbi));
    FARPROC  ntQueryInformationProcess;
    DWORD pid = GetProcessId("Taskmgr.exe");
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid);
    /*Run time Loading of Ntdll*/
    HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
    if(!hNTDLL)
        return 0;
    ntQueryInformationProcess = GetProcAddress(hNTDLL,"NtQueryInformationProcess");
    NTSTATUS status = ntQueryInformationProcess(proc,0,pbi,sizeof(pbi),opt);
    printf("Address %d\n",pbi->PebBaseAddress);
    perror("Error");
    return 0;
}
