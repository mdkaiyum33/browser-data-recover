// string_obfuscation.h
// String obfuscation utilities to avoid static analysis detection
// v0.15.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef STRING_OBFUSCATION_H
#define STRING_OBFUSCATION_H

#include <string>
#include <vector>
#include <cstdint>

namespace StringObf {
    
    // Simple XOR obfuscation with compile-time key
    template<size_t N>
    struct ObfuscatedString {
        constexpr ObfuscatedString(const char(&str)[N]) : key(0x5A) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ key ^ (i & 0xFF);
            }
        }
        
        std::string decrypt() const {
            std::string result;
            result.reserve(N);
            for (size_t i = 0; i < N - 1; ++i) {  // -1 to exclude null terminator
                result += static_cast<char>(data[i] ^ key ^ (i & 0xFF));
            }
            return result;
        }
        
    private:
        char data[N];
        uint8_t key;
    };
    
    // Simple wide string obfuscation
    template<size_t N>
    struct ObfuscatedWString {
        constexpr ObfuscatedWString(const wchar_t(&str)[N]) : key(0xA5) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ key ^ (i & 0xFF);
            }
        }
        
        std::wstring decrypt() const {
            std::wstring result;
            result.reserve(N);
            for (size_t i = 0; i < N - 1; ++i) {  // -1 to exclude null terminator
                result += static_cast<wchar_t>(data[i] ^ key ^ (i & 0xFF));
            }
            return result;
        }
        
    private:
        wchar_t data[N];
        uint8_t key;
    };
    
    // Runtime string deobfuscation
    inline std::string deobfuscate_runtime(const std::vector<uint8_t>& data, uint8_t key) {
        std::string result;
        result.reserve(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            result += static_cast<char>(data[i] ^ key ^ (i & 0xFF));
        }
        return result;
    }
    
    // Stack string clearing utility
    template<typename T>
    void secure_zero(T& str) {
        volatile char* ptr = const_cast<char*>(str.data());
        for (size_t i = 0; i < str.size(); ++i) {
            ptr[i] = 0;
        }
    }
}

// Macros for easy usage
#define OBFSTR(str) (StringObf::ObfuscatedString(str).decrypt())
#define OBFWSTR(str) (StringObf::ObfuscatedWString(str).decrypt())

// Stack-based temporary string that gets cleared
#define TEMP_STR(var, str) \
    auto var = OBFSTR(str); \
    auto var##_guard = [&]() { StringObf::secure_zero(var); }; \
    std::unique_ptr<void, decltype(var##_guard)> var##_cleanup(reinterpret_cast<void*>(1), var##_guard)

#endif // STRING_OBFUSCATION_H