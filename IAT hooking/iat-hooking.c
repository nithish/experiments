/*
EXP#1 IAT Hooking
Ref: https://github.com/m0n0ph1/IAT-Hooking-Revisited
     https://guidedhacking.com/threads/iat-hook-import-address-table-hooking-explained.4244/
     http://vexillium.org/?sec-dllsp
Date: 12/07/18
*/


#include<stdio.h>
#include<windows.h>
#include<winternl.h>
#include<WINNT.H>
void (hook)();
PROCESS_BASIC_INFORMATION *pbi;
int main()
{
    PULONG opt = 0;
    BYTE* procMem = malloc(BUFSIZ);
    FARPROC  ntQueryInformationProcess;
    short readSuccess = 0;
    long calVA =0,iidNameRva=0,e=0,mainVA,rva;
    IMAGE_IMPORT_DESCRIPTOR *iatDesc = malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    IMAGE_FILE_HEADER *ntfHdr = malloc(sizeof(IMAGE_FILE_HEADER)); 
    IMAGE_NT_HEADERS *ntHdr = malloc(sizeof(IMAGE_NT_HEADERS));
    IMAGE_DOS_HEADER *dosHdr = malloc(sizeof(IMAGE_DOS_HEADER));
    IMAGE_OPTIONAL_HEADER *optHdr = malloc(sizeof(IMAGE_OPTIONAL_HEADER));
    IMAGE_THUNK_DATA *fThunk = malloc(sizeof(IMAGE_THUNK_DATA));
    IMAGE_THUNK_DATA *ofThunk = malloc(sizeof(IMAGE_THUNK_DATA));
    IMAGE_IMPORT_BY_NAME *impByName,*funcAddr /*= malloc(sizeof(IMAGE_IMPORT_BY_NAME))*/;

    HMODULE mod = GetModuleHandle(0);
    DWORD va;
    dosHdr = (IMAGE_DOS_HEADER*) mod;
    ntHdr = (IMAGE_NT_HEADERS*) ((BYTE*) dosHdr+dosHdr->e_lfanew);
    ntfHdr = (IMAGE_FILE_HEADER*) &ntHdr->FileHeader;
    optHdr = (IMAGE_OPTIONAL_HEADER*) &ntHdr->OptionalHeader;
    va =  optHdr->DataDirectory[1].VirtualAddress;
    DWORD size =  optHdr->DataDirectory[1].Size;
    DWORD noFiles = size/sizeof(IMAGE_IMPORT_DESCRIPTOR);
    mainVA =(long) mod;
    rva = (long) va;
    
    
    
    printf("Base Address: %x\n",mod);
    printf("Dos Signature: %x\n",dosHdr->e_magic);
    printf("Nt Header: %x\n",ntHdr->Signature);
    printf("File Header: %x\n",ntfHdr->Machine);
    printf("Optional Header: %x\n",optHdr->Magic);
    /*
        Imported function has to be retrieved from OrginalFirstThunk 
        Address to the imported function has to be retrieved from FirstThunk
        Ref: https://msdn.microsoft.com/en-IN/library/ms809762.aspx
    */
    while(1){
        calVA = mainVA+rva;
        iatDesc = (IMAGE_IMPORT_DESCRIPTOR*) calVA;
        iidNameRva = (int) iatDesc->Name;
        char* ptr = malloc(sizeof(char*)); 
        ptr = (char*)(mainVA+iidNameRva);
        if(iidNameRva == 0)
            break;
        printf("\n\nImported File: %s\n",ptr);
        ofThunk = (IMAGE_THUNK_DATA*)iatDesc->OriginalFirstThunk;
        ofThunk = (IMAGE_THUNK_DATA*) (mainVA+(long)ofThunk);

        fThunk = (IMAGE_THUNK_DATA*)iatDesc->FirstThunk;
        fThunk = (IMAGE_THUNK_DATA*) (mainVA+(long)fThunk);
        
        printf("Name\tOrdinal\n");
        while(ofThunk->u1.AddressOfData && fThunk->u1.AddressOfData){
            funcAddr = (IMAGE_IMPORT_BY_NAME*)(mainVA + (long) ofThunk->u1.AddressOfData);
            if(strcmp((char *)funcAddr->Name,"DeleteCriticalSection")==0){
                DWORD old,temp;
                VirtualProtect(&fThunk->u1.Function,4,PAGE_EXECUTE_READWRITE,&old);
                fThunk->u1.Function = (DWORD)&hook;
                VirtualProtect(&old,4,PAGE_EXECUTE_READWRITE,&temp);
            }
            printf("%s  %d  0x%p\n",funcAddr->Name,funcAddr->Hint,fThunk->u1.Function);
            ofThunk++;fThunk++;
        }
        rva+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    perror("Thunk Error: ");

}

void hook(){
    printf("HELLOOOOOOOOOOOO NITIN\n\n");
}