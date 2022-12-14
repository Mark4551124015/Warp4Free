#include <windows.h>
#include <psapi.h>

#include <iostream>
#include <filesystem>
#include <string>
#include <vector>

#include "MinHook.h"

bool compare(const uint8_t* pData, const uint8_t* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask) {
            return 0;
        }
    }
    return (*szMask) == NULL;
}

uintptr_t find_pattern(uintptr_t dwAddress, uintptr_t dwLen, uint8_t* bMask, char* szMask) {
    for (uintptr_t i = 0; i < dwLen; i++) {
        if (compare((uint8_t*)(dwAddress + i), bMask, szMask)) {
            return dwAddress + i;
        }
    }
    return 0;
}

std::vector<std::string> split_str(std::string s, char delim) {
    std::vector<std::string> result;
    std::istringstream string_stream;
    string_stream.clear();
    string_stream.str(s);
    std::string temp;
    while (std::getline(string_stream, temp, delim))
        result.push_back(temp);
    return result;
}

uintptr_t scan_ida(std::string ida_pattern, uintptr_t start_address, size_t length) {
    std::vector<std::string> bytes = split_str(ida_pattern, ' ');
    std::string pattern = "", mask = "";

    for (auto& it : bytes) {
        if (it.size() && it[0] == '?') {
            mask += '?';
            pattern += '\0';
        }
        else {
            mask += 'x';
            pattern += (unsigned char)std::strtol(it.c_str(), NULL, 16);
        }
    }

    return find_pattern(start_address, length, (uint8_t*)pattern.c_str(), const_cast<char*>(mask.c_str()));
}

bool find_module(MODULEINFO* moduleInfo, const wchar_t* name) {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                if (std::wstring(szModName).find(name) != std::wstring::npos) {
                    return GetModuleInformation(hProcess, hMods[i], moduleInfo, sizeof(MODULEINFO));
                }
            }
        }
    }

    return false;
}

typedef __int64(__fastcall* t_ui_update)(__int64, int, int, float, int, __int64, __int64, void*, void*, __int64, int*);
t_ui_update h_ui_update_tramp = NULL;

__int64 __fastcall h_ui_update(__int64 a1, int a2, int a3, float a4, int a5, __int64 a6, __int64 a7, void* a8, void* a9, __int64 a10, int* a11) {
    *(__int64*)(*(__int64*)(a7 + 160)) = 0xFFFFFFFF;
    return h_ui_update_tramp(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

void start() {

#ifdef DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
#endif

    std::wcout << "Warp4Free Attached\n";

    // UI Update E8 ? ? ? ? 0F B6 4F 2C
    // Settings Menu Update 40 55 53 56 57 41 55

    MODULEINFO parsecdll{};
    if (!find_module(&parsecdll, L"parsecd-")) {
        MessageBox(NULL, L"Could not find dll", L"Error", MB_OK);
        return;
    }

    std::wcout << std::hex << (uintptr_t)parsecdll.lpBaseOfDll << '\n';

    uintptr_t ui_update_ptr_call = scan_ida("E8 ? ? ? ? 0F B6 4F 2C", (uintptr_t)parsecdll.lpBaseOfDll, parsecdll.SizeOfImage);
    uintptr_t ui_update_ptr = ui_update_ptr_call + *(uint32_t*)(ui_update_ptr_call + 1) + 5;

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