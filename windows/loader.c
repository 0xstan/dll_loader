#include <stdio.h>
#include <windows.h>
#include <winternl.h>

// Those two shellcodes are basically doing the same thing:
// They retrieve the address of LoadLibraryA without using any API
// and store the address in ebx.
UCHAR sc_32[] = 
{
    0x64,0x8b,0x15,0x30,0x00,0x00,0x00,0x8b,
    0x52,0x0c,0x8b,0x52,0x0c,0x52,0x8b,0x52,
    0x18,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,
    0x78,0x85,0xc0,0x74,0x45,0x01,0xd0,0x50,
    0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,
    0x85,0xc9,0x74,0x35,0x49,0x8b,0x34,0x8b,
    0x01,0xd6,0xbf,0x00,0x00,0x00,0x00,0x31,
    0xc0,0xac,0xc1,0xc7,0x07,0x01,0xc7,0x84,
    0xc0,0x75,0xf4,0x81,0xff,0x88,0xe4,0xff,
    0x6f,0x75,0xdd,0x58,0x8b,0x58,0x24,0x01,
    0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,
    0x01,0xd3,0x8b,0x1c,0x8b,0x01,0xd3,0xeb,
    0xfe,0x58,0x5a,0x8b,0x12,0xeb,0xa6
};

UCHAR sc_64[] = 
{
    0x65,0x48,0x8b,0x14,0x25,0x60,0x00,0x00,
    0x00,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
    0x10,0x52,0x48,0x8b,0x52,0x30,0x8b,0x42,
    0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,
    0x00,0x00,0x48,0x85,0xc0,0x74,0x4f,0x48,
    0x01,0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,
    0x20,0x48,0x01,0xd3,0x48,0x85,0xc9,0x74,
    0x3c,0x48,0xff,0xc9,0x8b,0x34,0x8b,0x48,
    0x01,0xd6,0xbf,0x00,0x00,0x00,0x00,0x48,
    0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,
    0x84,0xc0,0x75,0xf3,0x81,0xff,0x72,0x60,
    0x77,0x74,0x75,0xd8,0x58,0x8b,0x58,0x24,
    0x48,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,
    0x58,0x1c,0x48,0x01,0xd3,0x8b,0x1c,0x8b,
    0x48,0x01,0xd3,0xeb,0xfe,0x58,0x5a,0x48,
    0x8b,0x12,0xeb,0x95
};

// Get the entry point and determine if the binary is 32 or 64 bits.
DWORD 
get_entry_point_and_machine (
    UCHAR* path, 
    BOOL* is_32
    )
{
    FILE* fapp;
    if (fopen_s(&fapp, path, "r") != 0) 
    {
        printf("Can't open app\n");
        return 0;
    } 
    
    if (fseek(fapp, 0x3c, SEEK_SET)) 
    {
        printf("Can't fseek file\n");
        return 0;
    }

    DWORD pe_header_offset;
    UCHAR pe_header_offset_bytes[4];
    if (fread(pe_header_offset_bytes, 1, 4, fapp) == 0) 
    {
        printf("Can't read pe_header_offset_bytes\n");
        return 0;
    }

    pe_header_offset = *(DWORD*)pe_header_offset_bytes;

    if (fseek(fapp, pe_header_offset + 0x4, SEEK_SET)) {
        printf("Can't fseek file\n");
        return 0;
    }

    USHORT machine;
    UCHAR machine_bytes[2];
    if (fread(machine_bytes, 1, 2, fapp) == 0) {
        printf("Can't read machine_bytes\n");
        return 0;
    }

    machine = *(USHORT*)machine_bytes;
    if (machine == 0x14c) {
        printf("[+] Target process is 32 bits\n");
        *is_32 = 1;
    }
    else if (machine == 0x8664) {
        printf("[+] Target process is 64 bits\n");
        *is_32 = 0;
    }
    else {
        printf("Don't know that machine type\n");
        return 0;
    }

    if (fseek(fapp, pe_header_offset + 0x28, SEEK_SET)) {
        printf("Can't fseek file\n");
        return 0;
    }

    DWORD entry_point;
    UCHAR entry_point_bytes[4];
    if (fread(entry_point_bytes, 1, 4, fapp) == 0) {
        printf("Can't read entry_point_bytes\n");
        return 0;
    }

    entry_point = *(DWORD*)entry_point_bytes;

    return entry_point;
}

// Retrieve the PEB of the target Process
// !!! It appears that NtQueryInformationProcess on 32 bits binary
// from 64 bits one ( this one ) is returning the 64bits PEB of the 
// process.
PVOID 
GetPeb (
    HANDLE ProcessHandle
    )
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    PVOID pPeb = NULL;
    typedef NTSTATUS(NTAPI *pt_NtQryInfoProc) ( HANDLE,
                                                DWORD,
                                                PVOID,
                                                ULONG,
                                                PULONG);

    memset(&pbi, 0, sizeof(pbi));

    pt_NtQryInfoProc NtQueryInformationProcess = 
        (pt_NtQryInfoProc) GetProcAddress(  GetModuleHandle("ntdll.dll"),
                                            "NtQueryInformationProcess");

    if (NtQueryInformationProcess == 0) {
        printf("Can't retrieve adress of NtQueryInformationProcess\n");
        return 0;
    }

    status = NtQueryInformationProcess( ProcessHandle, 
                                        ProcessBasicInformation, 
                                        &pbi, 
                                        sizeof(pbi), 
                                        NULL);

    if (NT_SUCCESS(status)){
        pPeb = pbi.PebBaseAddress;
    }

    printf("[+] Target process PEB is at %p\n", pPeb);

    return pPeb;
}

// Those two functions are the same as NtQueryInformationProcess return 
// 64 bits PEB even on 32 bits process
UINT64 
get_image_base_32 (
    PROCESS_INFORMATION pi
    )
{
    UINT64 image_base;
    UCHAR image_base_bytes[8];
    SIZE_T nb_read;
    PVOID peb = GetPeb(pi.hProcess);

    if (!peb) {
        printf("Can't find address of peb\n");
        return 0;
    }

    ReadProcessMemory(  pi.hProcess,
                        (LPVOID)(peb + 0x10), 
                        image_base_bytes, 
                        8, 
                        &nb_read);

    image_base = *(UINT64*)image_base_bytes;

    return image_base;
}

UINT64 
get_image_base_64 (
    PROCESS_INFORMATION pi
    )
{
    UINT64 image_base;
    UCHAR image_base_bytes[8];
    SIZE_T nb_read;
    PVOID peb = GetPeb(pi.hProcess);

    if (!peb) {
        printf("Can't find address of peb\n");
        return 0;
    }

    ReadProcessMemory(  pi.hProcess, 
                        (LPVOID)(peb + 0x10), 
                        image_base_bytes, 
                        8, 
                        &nb_read);

    image_base = *(UINT64*)image_base_bytes;

    return image_base;
}

DWORD 
patch_entry_point (
    HANDLE process_handle, 
    UINT64 address_to_patch, 
    UCHAR* patch, 
    DWORD size_of_patch, 
    UCHAR* stolen_bytes
    )
{

    typedef NTSTATUS(NTAPI *pt_NtProtVirtMem)(  HANDLE, 
                                                PVOID, 
                                                PSIZE_T, 
                                                ULONG, 
                                                PULONG);

    pt_NtProtVirtMem NtProtectVirtualMemory = 
        (pt_NtProtVirtMem) GetProcAddress(  GetModuleHandle("ntdll.dll"), 
                                            "NtProtectVirtualMemory");

    if (NtProtectVirtualMemory == 0) {
        printf("Can't retrieve address of NtProtectVirtualMemory\n");
        return -1;
    }

    printf( "[+] NtProtectVirtualMemory is at %x\n", 
            NtProtectVirtualMemory);

    UINT64 tmp_address = address_to_patch; 

    SIZE_T size = size_of_patch;
    ULONG old_protect, tmp;
    SIZE_T nb_write, nb_read;
    INT rv;

    if ((rv = NtProtectVirtualMemory(   process_handle, 
                                        &tmp_address, 
                                        &size, 
                                        PAGE_READWRITE, 
                                        &old_protect)) != 0)
    {
        printf("NtProtectVirtualMemory failed %x\n", rv); 
        return -1;
    }

    if ((rv = ReadProcessMemory(    process_handle, 
                                    (LPCVOID)address_to_patch, 
                                    stolen_bytes, 
                                    size_of_patch, 
                                    &nb_read)) == 0)
    {
        printf("ReadProcessMemory failed\n"); 
        return -1;
    }

    if ((rv = WriteProcessMemory(   process_handle, 
                                    (LPVOID)address_to_patch, 
                                    patch, 
                                    size_of_patch, 
                                    &nb_write)) == 0) 
    {
        printf("WriteProcessMemory failed\n"); 
        return -1;
    }

    printf( "[+] Writed %x %x at %x\n", 
            patch[0], 
            patch[1], 
            address_to_patch);

    tmp_address = address_to_patch; 

    if ((rv = NtProtectVirtualMemory(   process_handle, 
                                        &tmp_address, 
                                        &size, 
                                        old_protect, 
                                        &tmp)) != 0) 
    {
        printf("NtProtectVirtualMemory failed\n"); 
        return -1;
    } 

    return 0;
}

DWORD 
wait_for_entry_point ( 
    PROCESS_INFORMATION pi, 
    UINT64 virtual_ep, 
    BOOL is_32
    )
{
    ResumeThread(pi.hThread);
    CONTEXT context;

    for ( DWORD i = 0; i < 50 && context.Rip != virtual_ep; ++i ){
        Sleep(100);
        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(pi.hThread, &context);
    }
    
    if ( context.Rip != virtual_ep){
        printf("Process does not seem to reach entry_point\n");
        return -1;
    }

    return 0;
}

DWORD 
inject_dll_32 (
    PROCESS_INFORMATION process, 
    UCHAR* dllpath
    )
{
    INT rv;
    LPVOID base_address = VirtualAllocEx(   process.hProcess, 
                                            0, 
                                            sizeof(sc_32), 
                                            MEM_RESERVE | MEM_COMMIT, 
                                            PAGE_EXECUTE_READWRITE);

    if (!base_address) 
    {
        printf("Can't virtual alloc\n");
        return -1;
    }

    printf("[+] Allocated region in process: %x\n", base_address);

    if ((rv = WriteProcessMemory(   process.hProcess,  
                                    base_address, 
                                    sc_32, 
                                    sizeof(sc_32), 
                                    NULL) == 0)) 
    {
        printf("Can't write into process memory\n");
        return -1;
    }

    printf("[+] Writed shellcode in process memory\n", dllpath); 

    HANDLE thread_id;

    if ((thread_id = CreateRemoteThread(    
                    process.hProcess, 
                    NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE) base_address, 
                    NULL, 
                    0, 
                    NULL)) == 0)
    {
        printf("Can't create remote thread\n");
        return -1;
    }

    printf("[+] Shellcode execution!\n");

    WOW64_CONTEXT context;
    for ( DWORD i = 0; i < 50 && context.Eip != base_address + 0x5f; ++i )
    {
        Sleep(100);
        context.ContextFlags = CONTEXT_FULL;
        Wow64SuspendThread(thread_id);
        Wow64GetThreadContext(thread_id, &context);
        ResumeThread(thread_id);
    }

    if ( context.Eip != base_address + 0x5f)
    {
        printf("Shellcode does not seem to find LoadLibraryA\n");
        return -1;
    }

    UINT64 LoadLibraryA = context.Ebx;
    printf("[+] LoadLibraryA is at %p\n", LoadLibraryA);
    SuspendThread(thread_id);

    LPVOID dll_path_address = (LPVOID) VirtualAllocEx(
            process.hProcess, 
            0, 
            strlen(dllpath), 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE);

    if (!dll_path_address) 
    {
        printf("Can't virtual alloc\n");
        return -1;
    }

    printf("[+] Allocated region in process: %x\n", dll_path_address);

    if ((rv = WriteProcessMemory(
                    process.hProcess, 
                    dll_path_address, 
                    dllpath, 
                    strlen(dllpath), 
                    NULL) == 0)) 
    {
        printf("Can't write into process memory\n");
        return -1;
    }

    printf("[+] Writed %s in process memory\n", dllpath); 

    if ((thread_id = CreateRemoteThread(
                    process.hProcess, 
                    NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE) LoadLibraryA, 
                    dll_path_address, 
                    0, 
                    NULL)) == 0)
    {
        printf("Can't create remote thread\n");
        return -1;
    }

    WaitForSingleObject(thread_id, INFINITE);
    VirtualFreeEx(process.hProcess, base_address, 0, MEM_RELEASE);
    printf("[+] Remote thread created\n");
    return 0;
}

DWORD 
inject_dll_64 (
    PROCESS_INFORMATION process, 
    UCHAR* dllpath
    )
{
    INT rv;
    LPVOID base_address = (LPVOID) VirtualAllocEx(
            process.hProcess, 
            0, 
            sizeof(sc_64), 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_EXECUTE_READWRITE);

    if (!base_address) 
    {
        printf("Can't virtual alloc\n");
        return -1;
    }

    printf("[+] Allocated region in process: %x\n", base_address);

    if ((rv = WriteProcessMemory(
                    process.hProcess, 
                    base_address, 
                    sc_64, 
                    sizeof(sc_64), 
                    NULL) == 0)) 
    {
        printf("Can't write into process memory\n");
        return -1;
    }

    printf("[+] Writed shellcode in process memory\n", dllpath); 

    HANDLE thread_id;
    if ((thread_id = CreateRemoteThread(
                    process.hProcess, 
                    NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE) base_address, 
                    NULL, 
                    0, 
                    NULL)) == 0)
    {
        printf("Can't create remote thread\n");
        return -1;
    }

    printf("[+] Shellcode execution!\n");
    CONTEXT context;

    for (   DWORD i = 0; 
            i < 50 && (LPVOID)context.Rip != base_address + 0x73;
            ++i )
    {
        Sleep(100);
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(thread_id, &context);
    }

    if ( (LPVOID)context.Rip != base_address + 0x73)
    {
        printf("Shellcode does not seem to find LoadLibraryA\n");
        return -1;
    }

    UINT64 LoadLibraryA = context.Rbx;
    printf("[+] LoadLibraryA is at %p\n", LoadLibraryA);
    SuspendThread(thread_id);

    LPVOID dll_path_address = (LPVOID) VirtualAllocEx(
            process.hProcess, 
            0, 
            strlen(dllpath), 
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!dll_path_address) 
    {
        printf("Can't virtual alloc\n");
        return -1;
    }

    printf("[+] Allocated region in process: %x\n", dll_path_address);

    if ((rv = WriteProcessMemory(
                    process.hProcess, 
                    dll_path_address, 
                    dllpath, 
                    strlen(dllpath), 
                    NULL) == 0)) 
    {
        printf("Can't write into process memory\n");
        return -1;
    }

    printf("[+] Writed %s in process memory\n", dllpath); 

    if ((thread_id = CreateRemoteThread(
                    process.hProcess, 
                    NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE) LoadLibraryA, 
                    dll_path_address, 
                    0, 
                    NULL)) == 0)
    {
        printf("Can't create remote thread\n");
        return -1;
    }

    WaitForSingleObject(thread_id, INFINITE);
    VirtualFreeEx(process.hProcess, base_address, 0, MEM_RELEASE);
    printf("[+] Remote thread created\n");
    return 0;
}

INT 
main (
    INT argc, 
    CHAR** argv
    )
{
    INT rv;
    if (argc < 3) 
    {
        printf("You must use ./%s binary_to_run.exe"
                " ARGS... dll_to_inject.dll\n", argv[0]);
        return -1; 
    }

    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
    StartupInfo.cb = sizeof(StartupInfo);

    CHAR buffer_args[1024] = {0};
    DWORD i;
    for (i = 0; i < argc - 2; i++) {
        strcat(buffer_args, argv[i + 1]);
        strcat(buffer_args, " ");
    }

    if ((rv = CreateProcessA(
                    argv[1], 
                    buffer_args, 
                    NULL, 
                    NULL, 
                    FALSE, 
                    CREATE_SUSPENDED, 
                    NULL, 
                    NULL, 
                    &StartupInfo, 
                    &ProcessInformation)) == 0) 
    {
        printf("Error creating the process: %i\n", GetLastError());
        return -1;
    }

    printf("[+] Process '%s' created suspended\n", buffer_args);

    BOOL is_32;
    DWORD address_entry_point = get_entry_point_and_machine(argv[1], &is_32);

    if (!address_entry_point) 
    {
        printf("Wrong address of entry_point\n");
        return -1;
    }

    UINT64 address_image_base;
    if (is_32) 
    {
        address_image_base = get_image_base_32(ProcessInformation);
    }
    else 
    {
        address_image_base = get_image_base_64(ProcessInformation);
    }

    if (!address_image_base) 
    {
        printf("Wrong address of image_base\n");
        return -1;
    }

    UINT64 virtual_ep = address_image_base + address_entry_point;
    printf("[+] entrypoint is at %x\n", address_entry_point);
    printf("[+] image_base is at %x\n", address_image_base);
    printf("[+] Virtual entrypoint is at %x\n", virtual_ep);
    
    UCHAR patch[2] = {0xEB, 0xFE};
    UCHAR stolen_bytes[2] = {0, 0};
    if (patch_entry_point(
                ProcessInformation.hProcess, 
                virtual_ep, 
                patch, 
                sizeof(patch), 
                stolen_bytes)) 
    {
        printf("patch_entry_point failed\n");
        return -1;
    }

    printf("[+] Saved stolen bytes %x %x\n", stolen_bytes[0], stolen_bytes[1]);
    
    if (wait_for_entry_point(ProcessInformation, virtual_ep, is_32))
    {
        printf("wait_for_entry_point\n");
        return -1;
    };

    if (is_32) 
    {
        if (inject_dll_32(ProcessInformation, argv[argc - 1]))
        {
            printf("Can't inject dll\n");
            return -1;
        }
    }
    else 
    {
        if (inject_dll_64(ProcessInformation, argv[argc - 1])) 
        {
            printf("Can't inject dll\n");
            return -1;
        }
    }

    printf("[+] Dll successfully injected\n");
    SuspendThread(ProcessInformation.hThread);
    if 
    (
        patch_entry_point
        (
            ProcessInformation.hProcess, 
            virtual_ep, 
            stolen_bytes, 
            sizeof(patch), 
            patch
        )
    ) 
    {
        printf("patch_entry_point failed\n");
        return -1;
    }

    printf("[+] Saved stolen bytes restored\n");
    ResumeThread(ProcessInformation.hThread);
    WaitForSingleObject(ProcessInformation.hThread, INFINITE);
    return 0;
}

