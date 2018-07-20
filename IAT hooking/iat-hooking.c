/*
EXP#1 IAT Hooking
Ref: https://github.com/m0n0ph1/IAT-Hooking-Revisited
Date: 12/07/18

typedef struct _PROCESS_BASIC_INFORMATION{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
*/


#include<stdio.h>
#include<windows.h>
#include<winternl.h>
#include<WINNT.H>

PROCESS_BASIC_INFORMATION *pbi;
int main()
{
    PULONG opt = 0;
    BYTE* procMem = malloc(BUFSIZ);
    pbi = malloc(sizeof(*pbi));
    FARPROC  ntQueryInformationProcess;
    short readSuccess = 0;
    IMAGE_IMPORT_DESCRIPTOR *iatDesc = malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    IMAGE_NT_HEADERS64 *ntHdr = malloc(sizeof(IMAGE_NT_HEADERS64));
    // DWORD pid = GetProcessId("Taskmgr.exe");
    // printf("Pid: %d\n",pid);
    HANDLE proc = OpenProcess(PROCESS_VM_READ,FALSE,GetCurrentProcessId());
    if(proc == NULL)
        printf("Error opening process %d\n",GetLastError());
    /*Run time Loading of Ntdll*/
    HMODULE hNTDLL = LoadLibrary(TEXT("ntdll.dll"));
    if(!hNTDLL)
        return 0;
    ntQueryInformationProcess = GetProcAddress(hNTDLL,"NtQueryInformationProcess");
    NTSTATUS status = ntQueryInformationProcess(proc,0,pbi,sizeof(pbi),opt);
    printf("Address %d\n",pbi->PebBaseAddress);
    perror("Error");
    readSuccess = ReadProcessMemory(
        proc,
        pbi->PebBaseAddress,
        procMem,
        BUFSIZ,
        0
    );
    printf("ReadProcessMemory Error code: %d\n",readSuccess);
    printf("ProcMem: %d\n",procMem);
    if(!readSuccess){
        perror("Failed to read Process memory");
        printf("Status: %d\n",readSuccess);
    }
    ntHdr = (IMAGE_NT_HEADERS64*) procMem;
    printf("Signature: %x\n",ntHdr->Signature);
    perror("Error");
    return 0;
}
