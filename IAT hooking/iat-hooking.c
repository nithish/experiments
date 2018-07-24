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
    IMAGE_THUNK_DATA *fThunk = malloc(sizeof(IMAGE_THUNK_DATA));
    IMAGE_IMPORT_BY_NAME  *impByName,*funcAddr = malloc(sizeof(IMAGE_IMPORT_BY_NAME));

    HMODULE mod = GetModuleHandle(0);
    DWORD va;
    dosHdr = (IMAGE_DOS_HEADER*) mod;
    ntHdr = (IMAGE_NT_HEADERS*) ((BYTE*) dosHdr+dosHdr->e_lfanew);
    ntfHdr = (IMAGE_FILE_HEADER*) &ntHdr->FileHeader;
    optHdr = (IMAGE_OPTIONAL_HEADER*) &ntHdr->OptionalHeader;
    va =  optHdr->DataDirectory[1].VirtualAddress;
    DWORD size =  optHdr->DataDirectory[1].Size;
    DWORD noFiles = size/sizeof(IMAGE_IMPORT_DESCRIPTOR);
    int a =(int) mod;
    int b = (int) va;
    int c =0,d=0,e=0;
    
    
    printf("Base Address: %x\n",mod);
    printf("Dos Signature: %x\n",dosHdr->e_magic);
    printf("Nt Header: %x\n",ntHdr->Signature);
    printf("File Header: %x\n",ntfHdr->Machine);
    printf("Optional Header: %x\n",optHdr->Magic);
    
    while(1){
        c= a+b;
        iatDesc = (IMAGE_IMPORT_DESCRIPTOR*) c;
        d = (int) iatDesc->Name;
        char* ptr = malloc(sizeof(char*)); 
        ptr = (char*)(a+d);
        if(d == 0)
            break;
        printf("Imported File: %s\n",ptr);
        fThunk = (IMAGE_THUNK_DATA*) &iatDesc->FirstThunk;
        while(1){
            impByName = (IMAGE_IMPORT_BY_NAME*) &fThunk->u1;
            funcAddr = (IMAGE_IMPORT_BY_NAME*)(&fThunk->u1.AddressOfData);//check
            int t = (int) funcAddr->Hint;
            long* u = (long*) (a+t);

            printf("Hint: %s\n",*u);
            if(impByName->Hint == 0)
                break;
            int x = (int)fThunk;
            int y = x+sizeof(IMAGE_THUNK_DATA);
            fThunk = (IMAGE_THUNK_DATA*) y;
        }
        b+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    perror("Thunk Error: ");

}
