// syscalls.cpp
// v0.15.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "syscalls.h"
#include "string_obfuscation.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <map>
#include <functional>
#include <random>
#include <thread>
#include <chrono>

SYSCALL_STUBS g_syscall_stubs{};

static bool g_verbose_syscalls = false;
static void debug_print(const std::string &msg)
{
    if (g_verbose_syscalls)
    {
        std::cout << "[#] " << msg << std::endl;
    }
}

extern "C" NTSTATUS SyscallTrampoline(...);

namespace
{
    struct SORTED_SYSCALL_MAPPING
    {
        PVOID pAddress;
        LPCSTR szName;
    };

    bool CompareSyscallMappings(const SORTED_SYSCALL_MAPPING &a, const SORTED_SYSCALL_MAPPING &b)
    {
        return reinterpret_cast<uintptr_t>(a.pAddress) < reinterpret_cast<uintptr_t>(b.pAddress);
    }

    PVOID FindSyscallGadget_x64(PVOID pFunction)
    {
        for (DWORD i = 0; i <= 64; ++i)
        {
            auto current_addr = reinterpret_cast<PBYTE>(pFunction) + i;

            if (*current_addr == 0xE9) // jmp rel32
            {
                i += 4;
                continue;
            }

            if (*reinterpret_cast<PWORD>(current_addr) == 0x050F && *(current_addr + 2) == 0xC3)
            {
                return current_addr;
            }
        }
        return nullptr;
    }

    PVOID FindSvcGadget_ARM64(PVOID pFunction)
    {
        for (DWORD i = 0; i <= 64; i += 4)
        {
            auto current_addr = reinterpret_cast<PBYTE>(pFunction) + i;
            DWORD instruction = *reinterpret_cast<PDWORD>(current_addr);

            if ((instruction & 0xFC000000) == 0x14000000) // B <offset>
            {
                continue;
            }

            if ((instruction & 0xFF000000) == 0xD4000000 && *reinterpret_cast<PDWORD>(current_addr + 4) == 0xD65F03C0)
            {
                return current_addr;
            }
        }
        return nullptr;
    }
}

BOOL InitializeSyscalls(bool is_verbose)
{
    g_verbose_syscalls = is_verbose;
    
    // Add some entropy and timing variation
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 100);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));

    // Obfuscated module name
    TEMP_STR(ntdll_name, "ntdll.dll");
    std::wstring wntdll_name(ntdll_name.begin(), ntdll_name.end());
    
    HMODULE hNtdll = GetModuleHandleW(wntdll_name.c_str());
    if (!hNtdll)
    {
        TEMP_STR(err_msg, "GetModuleHandleW for system library failed.");
        debug_print(err_msg);
        return FALSE;
    }

    auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(hNtdll) + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PBYTE>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto pNameRvas = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfNames);
    auto pAddressRvas = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfFunctions);
    auto pOrdinalRvas = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    std::vector<SORTED_SYSCALL_MAPPING> sortedSyscalls;
    sortedSyscalls.reserve(pExportDir->NumberOfNames);

    // Obfuscated prefix check
    TEMP_STR(prefix, "Zw");
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        LPCSTR szFuncName = reinterpret_cast<LPCSTR>(reinterpret_cast<PBYTE>(hNtdll) + pNameRvas[i]);
        if (strncmp(szFuncName, prefix.c_str(), 2) == 0)
        {
            PVOID pFuncAddress = reinterpret_cast<PVOID>(reinterpret_cast<PBYTE>(hNtdll) + pAddressRvas[pOrdinalRvas[i]]);
            sortedSyscalls.push_back({pFuncAddress, szFuncName});
        }
    }

    std::sort(sortedSyscalls.begin(), sortedSyscalls.end(), CompareSyscallMappings);
    debug_print("Found and sorted " + std::to_string(sortedSyscalls.size()) + " Zw* functions.");

    // Use runtime obfuscation for syscall names
    std::map<std::string, std::pair<SYSCALL_ENTRY *, UINT>> required_syscalls;
    
    // Build the map with obfuscated strings
    required_syscalls[OBFSTR("ZwAllocateVirtualMemory")] = {&g_syscall_stubs.NtAllocateVirtualMemory, 6};
    required_syscalls[OBFSTR("ZwWriteVirtualMemory")] = {&g_syscall_stubs.NtWriteVirtualMemory, 5};
    required_syscalls[OBFSTR("ZwReadVirtualMemory")] = {&g_syscall_stubs.NtReadVirtualMemory, 5};
    required_syscalls[OBFSTR("ZwCreateThreadEx")] = {&g_syscall_stubs.NtCreateThreadEx, 11};
    required_syscalls[OBFSTR("ZwFreeVirtualMemory")] = {&g_syscall_stubs.NtFreeVirtualMemory, 4};
    required_syscalls[OBFSTR("ZwProtectVirtualMemory")] = {&g_syscall_stubs.NtProtectVirtualMemory, 5};
    required_syscalls[OBFSTR("ZwOpenProcess")] = {&g_syscall_stubs.NtOpenProcess, 4};
    required_syscalls[OBFSTR("ZwGetNextProcess")] = {&g_syscall_stubs.NtGetNextProcess, 5};
    required_syscalls[OBFSTR("ZwTerminateProcess")] = {&g_syscall_stubs.NtTerminateProcess, 2};
    required_syscalls[OBFSTR("ZwQueryInformationProcess")] = {&g_syscall_stubs.NtQueryInformationProcess, 5};
    required_syscalls[OBFSTR("ZwUnmapViewOfSection")] = {&g_syscall_stubs.NtUnmapViewOfSection, 2};
    required_syscalls[OBFSTR("ZwGetContextThread")] = {&g_syscall_stubs.NtGetContextThread, 2};
    required_syscalls[OBFSTR("ZwSetContextThread")] = {&g_syscall_stubs.NtSetContextThread, 2};
    required_syscalls[OBFSTR("ZwResumeThread")] = {&g_syscall_stubs.NtResumeThread, 2};
    required_syscalls[OBFSTR("ZwFlushInstructionCache")] = {&g_syscall_stubs.NtFlushInstructionCache, 3};
    required_syscalls[OBFSTR("ZwClose")] = {&g_syscall_stubs.NtClose, 1};
    required_syscalls[OBFSTR("ZwOpenKey")] = {&g_syscall_stubs.NtOpenKey, 3};
    required_syscalls[OBFSTR("ZwQueryValueKey")] = {&g_syscall_stubs.NtQueryValueKey, 6};
    required_syscalls[OBFSTR("ZwEnumerateKey")] = {&g_syscall_stubs.NtEnumerateKey, 6};

    for (WORD i = 0; i < sortedSyscalls.size(); ++i)
    {
        const auto &mapping = sortedSyscalls[i];
        auto it = required_syscalls.find(mapping.szName);
        if (it == required_syscalls.end())
        {
            continue;
        }

        PVOID pGadget = nullptr;
#if defined(_M_X64)
        pGadget = FindSyscallGadget_x64(mapping.pAddress);
#elif defined(_M_ARM64)
        pGadget = FindSvcGadget_ARM64(mapping.pAddress);
#endif

        if (pGadget)
        {
            it->second.first->pSyscallGadget = pGadget;
            it->second.first->nArgs = it->second.second;
            it->second.first->ssn = i;
        }
    }

    bool all_found = true;
    for (const auto &pair : required_syscalls)
    {
        if (!pair.second.first->pSyscallGadget)
        {
            all_found = false;
            break;
        }
    }

    if (all_found)
    {
        int regSyscalls = 0;
        if (g_syscall_stubs.NtOpenKey.pSyscallGadget)
            regSyscalls++;
        if (g_syscall_stubs.NtQueryValueKey.pSyscallGadget)
            regSyscalls++;
        if (g_syscall_stubs.NtEnumerateKey.pSyscallGadget)
            regSyscalls++;

        debug_print("Initialized " + std::to_string(required_syscalls.size()) + " syscall stubs.");

        for (const auto &pair : required_syscalls)
        {
            if (!pair.second.first->pSyscallGadget)
            {
                debug_print("  WARNING: " + std::string(pair.first + 2) + " gadget not found");
            }
        }
    }
    else
    {
        debug_print("ERROR: One or more required syscall gadgets could not be found:");
        for (const auto &pair : required_syscalls)
        {
            if (!pair.second.first->pSyscallGadget)
            {
                debug_print("  - " + std::string(pair.first + 2) + " FAILED");
            }
        }
    }

    return all_found;
}

NTSTATUS NtAllocateVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtWriteVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtReadVirtualMemory_syscall(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtReadVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NtCreateThreadEx_syscall(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, LPVOID AttributeList)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtFreeVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS NtProtectVirtualMemory_syscall(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NtOpenProcess_syscall(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtOpenProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NtGetNextProcess_syscall(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtGetNextProcess, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
}

NTSTATUS NtTerminateProcess_syscall(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtTerminateProcess, ProcessHandle, ExitStatus);
}

NTSTATUS NtQueryInformationProcess_syscall(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NtUnmapViewOfSection_syscall(HANDLE ProcessHandle, PVOID BaseAddress)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtUnmapViewOfSection, ProcessHandle, BaseAddress);
}

NTSTATUS NtGetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtGetContextThread, ThreadHandle, pContext);
}

NTSTATUS NtSetContextThread_syscall(HANDLE ThreadHandle, PCONTEXT pContext)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtSetContextThread, ThreadHandle, pContext);
}

NTSTATUS NtResumeThread_syscall(HANDLE ThreadHandle, PULONG SuspendCount)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtResumeThread, ThreadHandle, SuspendCount);
}

NTSTATUS NtFlushInstructionCache_syscall(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtFlushInstructionCache, ProcessHandle, BaseAddress, NumberOfBytesToFlush);
}

NTSTATUS NtClose_syscall(HANDLE Handle)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtClose, Handle);
}

NTSTATUS NtOpenKey_syscall(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtOpenKey, KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS NtQueryValueKey_syscall(HANDLE KeyHandle, PUNICODE_STRING_SYSCALLS ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtQueryValueKey, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

NTSTATUS NtEnumerateKey_syscall(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    return (NTSTATUS)SyscallTrampoline(&g_syscall_stubs.NtEnumerateKey, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
}
