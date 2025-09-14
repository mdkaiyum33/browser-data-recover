#include "src/string_obfuscation.h"
#include <iostream>
#include <string>

int main() {
    // Test basic string obfuscation
    auto test1 = OBFSTR("Hello World");
    std::cout << "Obfuscated string: " << test1 << std::endl;
    
    // Test wide string obfuscation
    auto test2 = OBFWSTR(L"Wide String Test");
    std::wcout << L"Obfuscated wide string: " << test2 << std::endl;
    
    // Test temporary string with auto-cleanup
    {
        TEMP_STR(temp_str, "Temporary String");
        std::cout << "Temp string: " << temp_str << std::endl;
    } // temp_str is automatically cleared here
    
    return 0;
}