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
    FARPROC  ntQueryInformationProcess;
    short readSuccess = 0;

    IMAGE_IMPORT_DESCRIPTOR *iatDesc = malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    IMAGE_FILE_HEADER *ntfHdr = malloc(sizeof(IMAGE_FILE_HEADER)); 
    IMAGE_NT_HEADERS *ntHdr = malloc(sizeof(IMAGE_NT_HEADERS));
    IMAGE_DOS_HEADER *dosHdr = malloc(sizeof(IMAGE_DOS_HEADER));
    IMAGE_OPTIONAL_HEADER *optHdr = malloc(sizeof(IMAGE_OPTIONAL_HEADER));
    
    HMODULE mod = GetModuleHandle(0);
    
    dosHdr = (IMAGE_DOS_HEADER*) mod;
    ntHdr = (IMAGE_NT_HEADERS*) ((BYTE*) dosHdr+dosHdr->e_lfanew);
    ntfHdr = (IMAGE_FILE_HEADER*) &ntHdr->FileHeader;
    optHdr = (IMAGE_OPTIONAL_HEADER*) &ntHdr->OptionalHeader;

    printf("Dos Signature: %x\n",dosHdr->e_lfanew);
    printf("Nt Header: %x\n",ntHdr->Signature);
    printf("File Header: %x\n",ntfHdr->Machine);
    printf("Optional Header: %x\n",optHdr->Magic);


}
