#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <winternl.h>

#include <sstream>

namespace
{
    using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
    using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
    using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using LdrLoadDllFn = NTSTATUS(NTAPI*)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);

    LoadLibraryWFn real_LoadLibraryW = nullptr;
    LoadLibraryExWFn real_LoadLibraryExW = nullptr;
    GetProcAddressFn real_GetProcAddress = nullptr;
    LdrLoadDllFn real_LdrLoadDll = nullptr;

    HMODULE WINAPI detour_LoadLibraryW(LPCWSTR file_name)
    {
        if (mrtw::hook_guard) return real_LoadLibraryW(file_name);
        mrtw::HookGuard guard;
        HMODULE result = real_LoadLibraryW(file_name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Module","action":"LoadLibraryW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HMODULE WINAPI detour_LoadLibraryExW(LPCWSTR file_name, HANDLE file, DWORD flags)
    {
        if (mrtw::hook_guard) return real_LoadLibraryExW(file_name, file, flags);
        mrtw::HookGuard guard;
        HMODULE result = real_LoadLibraryExW(file_name, file, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Module","action":"LoadLibraryExW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    FARPROC WINAPI detour_GetProcAddress(HMODULE module, LPCSTR proc_name)
    {
        if (mrtw::hook_guard) return real_GetProcAddress(module, proc_name);
        mrtw::HookGuard guard;
        FARPROC result = real_GetProcAddress(module, proc_name);
        std::string name;
        if (reinterpret_cast<uintptr_t>(proc_name) > 0xffff)
        {
            name = proc_name == nullptr ? std::string{} : std::string(proc_name);
        }
        std::ostringstream json;
        json << R"({"source":"hook","category":"Module","action":"GetProcAddress","pid":)" << mrtw::current_pid()
             << R"(,"module":)" << reinterpret_cast<uintptr_t>(module)
             << R"(,"proc_name":)" << mrtw::q(name)
             << R"(,"ordinal":)" << (reinterpret_cast<uintptr_t>(proc_name) <= 0xffff ? reinterpret_cast<uintptr_t>(proc_name) : 0)
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result) << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    NTSTATUS NTAPI detour_LdrLoadDll(PWSTR path_to_file, ULONG flags, PUNICODE_STRING module_file_name, PHANDLE module_handle)
    {
        if (mrtw::hook_guard) return real_LdrLoadDll(path_to_file, flags, module_file_name, module_handle);
        std::wstring module;
        if (module_file_name != nullptr && module_file_name->Buffer != nullptr)
        {
            module.assign(module_file_name->Buffer, module_file_name->Length / sizeof(wchar_t));
        }
        mrtw::HookGuard guard;
        NTSTATUS status = real_LdrLoadDll(path_to_file, flags, module_file_name, module_handle);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Module","action":"LdrLoadDll","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(module))
             << R"(,"flags":)" << flags
             << R"(,"status":)" << status << "}";
        mrtw::emit_event(json.str());
        return status;
    }
}

namespace mrtw
{
    bool install_module_hooks()
    {
        LoadLibraryW(L"ntdll.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "LoadLibraryW", reinterpret_cast<LPVOID>(&detour_LoadLibraryW), reinterpret_cast<LPVOID*>(&real_LoadLibraryW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "LoadLibraryExW", reinterpret_cast<LPVOID>(&detour_LoadLibraryExW), reinterpret_cast<LPVOID*>(&real_LoadLibraryExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "GetProcAddress", reinterpret_cast<LPVOID>(&detour_GetProcAddress), reinterpret_cast<LPVOID*>(&real_GetProcAddress)) == MH_OK;
        ok &= MH_CreateHookApi(L"ntdll.dll", "LdrLoadDll", reinterpret_cast<LPVOID>(&detour_LdrLoadDll), reinterpret_cast<LPVOID*>(&real_LdrLoadDll)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"module_hooks_installed"})" : R"({"source":"hook","event":"module_hooks_failed"})");
        return ok;
    }
}
