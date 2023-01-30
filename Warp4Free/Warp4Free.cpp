#include <windows.h>
#include <psapi.h>

#include <iostream>
#include <filesystem>
#include <string>
#include <vector>

#include "MinHook.h"

bool compare(const uint8_t* address, const uint8_t* pattern, const char* mask) {
    for (; *mask; ++mask, ++address, ++pattern) {
        if (*mask == 'x' && *address != *pattern) {
            return 0;
        }
    }
    return (*mask) == NULL;
}

uintptr_t find_pattern(uintptr_t start_address, uintptr_t length, uint8_t* pattern, char* mask) {
    for (uintptr_t i = 0; i < length; i++) {
        if (compare((uint8_t*)(start_address + i), pattern, mask)) {
            return start_address + i;
        }
    }
    return 0;
}

std::vector<std::string> split_str(std::string input, char delim) {
    std::vector<std::string> result;
    size_t length = input.length();
    for (size_t index = 0; index < length; index++) {
        size_t pos = input.find(delim, index);
        result.push_back(input.substr(index, pos - index));
        if (pos > length) break;
        index = pos;
    }
    return result;
}

uintptr_t scan_ida(std::string ida_pattern, uintptr_t start_address, size_t length) {
    std::vector<std::string> bytes = split_str(ida_pattern, ' ');
    std::string pattern = "", mask = "";

    for (std::string& it : bytes) {
        if (it.size() && it[0] == '?') {
            mask += '?';
            pattern += '\0';
        }
        else {
            mask += 'x';
            pattern += (uint8_t)std::strtol(it.c_str(), NULL, 16);
        }
    }

    return find_pattern(start_address, length, (uint8_t*)pattern.c_str(), const_cast<char*>(mask.c_str()));
}

bool find_module(MODULEINFO* module_info, const wchar_t* name) {
    HMODULE modules[1024];
    HANDLE process = GetCurrentProcess();
    DWORD bytes_needed;

    if (EnumProcessModules(process, modules, sizeof(modules), &bytes_needed)) {
        for (int32_t i = 0; i < (bytes_needed / sizeof(HMODULE)); i++) {
            TCHAR module_name[MAX_PATH];
            if (GetModuleFileNameEx(process, modules[i], module_name, sizeof(module_name) / sizeof(TCHAR))) {
                if (std::wstring(module_name).find(name) != std::wstring::npos) {
                    return GetModuleInformation(process, modules[i], module_info, sizeof(MODULEINFO));
                }
            }
        }
    }

    return false;
}

typedef __int64(__fastcall* t_ui_update)(__int64, int, int, float, int, __int64, __int64, void*, void*, __int64, int*);
t_ui_update h_ui_update_tramp = NULL;

__int64 __fastcall h_ui_update(__int64 a1, int a2, int a3, float a4, int a5, __int64 a6, __int64 a7, void* a8, void* a9, __int64 a10, int* a11) {
    static bool printed = false;
    if (!printed) {
        printed = true;
        std::wcout << "Arg 7 Address: " << std::hex << a7 << std::dec << '\n';
    }

    auto permissions = *(__int64*)(a7 + 160);
    *(__int64*)(permissions) = 0xFFFFFFFFFFFFFFFF;

    return h_ui_update_tramp(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

void start() {

#ifdef _DEBUG
    AllocConsole();
    FILE* stream{};
    freopen_s(&stream, "CONOUT$", "w", stdout);
#endif

    std::wcout << "Warp4Free Attached\n";

    // UI Update E8 ? ? ? ? 0F B6 4F 2C
    // Settings Menu Update 40 55 53 56 57 41 55

    MODULEINFO parsecdll{};
    if (!find_module(&parsecdll, L"parsecd-")) {
        MessageBox(NULL, L"Could not find dll", L"Error", MB_OK);
        return;
    }

    std::wcout << std::hex << "Module Base: " << (uintptr_t)parsecdll.lpBaseOfDll << '\n';

    uintptr_t ui_update_ptr_call = scan_ida("E8 ? ? ? ? 0F B6 4F 2C", (uintptr_t)parsecdll.lpBaseOfDll, parsecdll.SizeOfImage);
    uintptr_t ui_update_ptr = ui_update_ptr_call + *(int32_t*)(ui_update_ptr_call + 1) + 5;

    std::wcout << std::hex << "UI Update: " << ui_update_ptr << '\n';

    if (MH_Initialize() != MH_OK)
        return;


    if (MH_CreateHook((void*)ui_update_ptr, &h_ui_update, reinterpret_cast<LPVOID*>(&h_ui_update_tramp)) != MH_OK)
        return;

    if (MH_EnableHook((void*)ui_update_ptr) != MH_OK)
        return;
    

    std::wcout << "Hooked!\n";
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        start();
    }
    return TRUE;
}