// evasion_utils.h
// Additional evasion utilities to avoid detection
// v0.15.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef EVASION_UTILS_H
#define EVASION_UTILS_H

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <algorithm>

namespace EvasionUtils {
    
    // Add random delays to break timing-based detection
    inline void RandomDelay(DWORD min_ms = 50, DWORD max_ms = 200) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }
    
    // Break up large allocations to avoid memory pattern detection
    inline std::vector<LPVOID> FragmentedAlloc(SIZE_T total_size, SIZE_T fragment_size = 4096) {
        std::vector<LPVOID> fragments;
        SIZE_T remaining = total_size;
        
        while (remaining > 0) {
            SIZE_T alloc_size = min(remaining, fragment_size);
            LPVOID ptr = VirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (ptr) {
                fragments.push_back(ptr);
                remaining -= alloc_size;
            } else {
                // Cleanup on failure
                for (auto p : fragments) {
                    VirtualFree(p, 0, MEM_RELEASE);
                }
                return {};
            }
            RandomDelay(10, 50);
        }
        
        return fragments;
    }
    
    // Cleanup fragmented allocation
    inline void CleanupFragmented(const std::vector<LPVOID>& fragments) {
        for (auto ptr : fragments) {
            if (ptr) {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
    }
    
    // Add entropy to avoid static signatures
    inline void AddEntropy() {
        static volatile DWORD entropy = 0;
        entropy ^= GetTickCount();
        entropy = (entropy << 13) | (entropy >> 19);  // Rotate
        entropy += GetCurrentThreadId();
    }
    
    // Simple process name obfuscation
    inline std::string ObfuscateProcessName(const std::string& name) {
        std::string result = name;
        for (auto& c : result) {
            c ^= 0x42;  // Simple XOR
        }
        return result;
    }
    
    // Check if running with suspicious parent processes
    inline bool HasSuspiciousParent() {
        DWORD current_pid = GetCurrentProcessId();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        
        DWORD parent_pid = 0;
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == current_pid) {
                    parent_pid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        
        if (parent_pid == 0) {
            CloseHandle(snapshot);
            return false;
        }
        
        // Check parent process name
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == parent_pid) {
                    std::wstring parent_name = pe32.szExeFile;
                    std::transform(parent_name.begin(), parent_name.end(), parent_name.begin(), ::towlower);
                    
                    // Common analysis tools
                    if (parent_name.find(L"wireshark") != std::wstring::npos ||
                        parent_name.find(L"procmon") != std::wstring::npos ||
                        parent_name.find(L"processhacker") != std::wstring::npos ||
                        parent_name.find(L"x64dbg") != std::wstring::npos ||
                        parent_name.find(L"ollydbg") != std::wstring::npos) {
                        CloseHandle(snapshot);
                        return true;
                    }
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        return false;
    }
}

#endif // EVASION_UTILS_H