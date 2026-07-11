#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <sstream>

namespace
{
    using CreateToolhelp32SnapshotFn = HANDLE(WINAPI*)(DWORD, DWORD);
    using Process32FirstWFn = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
    using Process32NextWFn = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
    using FindFirstFileWFn = HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
    using FindNextFileWFn = BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW);
    using RegEnumKeyExWFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
    using RegEnumValueWFn = LSTATUS(WINAPI*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using EnumProcessesFn = BOOL(WINAPI*)(DWORD*, DWORD, DWORD*);

    CreateToolhelp32SnapshotFn real_CreateToolhelp32Snapshot = nullptr;
    Process32FirstWFn real_Process32FirstW = nullptr;
    Process32NextWFn real_Process32NextW = nullptr;
    FindFirstFileWFn real_FindFirstFileW = nullptr;
    FindNextFileWFn real_FindNextFileW = nullptr;
    RegEnumKeyExWFn real_RegEnumKeyExW = nullptr;
    RegEnumValueWFn real_RegEnumValueW = nullptr;
    EnumProcessesFn real_EnumProcesses = nullptr;

    void emit_discovery(const char* action, const std::string& object, DWORD flags = 0, DWORD target = 0, BOOL result = TRUE)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":)" << mrtw::q(action)
             << R"(,"pid":)" << mrtw::current_pid()
             << R"(,"object":)" << mrtw::q(object)
             << R"(,"flags":)" << flags
             << R"(,"target_pid":)" << target
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
    }

    HANDLE WINAPI detour_CreateToolhelp32Snapshot(DWORD flags, DWORD process_id)
    {
        if (mrtw::hook_guard) return real_CreateToolhelp32Snapshot(flags, process_id);
        mrtw::HookGuard guard;
        HANDLE result = real_CreateToolhelp32Snapshot(flags, process_id);
        emit_discovery("CreateToolhelp32Snapshot", "process/module snapshot", flags, process_id, result != INVALID_HANDLE_VALUE);
        return result;
    }

    BOOL WINAPI detour_Process32FirstW(HANDLE snapshot, LPPROCESSENTRY32W entry)
    {
        if (mrtw::hook_guard) return real_Process32FirstW(snapshot, entry);
        mrtw::HookGuard guard;
        BOOL result = real_Process32FirstW(snapshot, entry);
        emit_discovery("Process32FirstW", result && entry != nullptr ? mrtw::narrow(entry->szExeFile) : "", 0, result && entry != nullptr ? entry->th32ProcessID : 0, result);
        return result;
    }

    BOOL WINAPI detour_Process32NextW(HANDLE snapshot, LPPROCESSENTRY32W entry)
    {
        if (mrtw::hook_guard) return real_Process32NextW(snapshot, entry);
        mrtw::HookGuard guard;
        BOOL result = real_Process32NextW(snapshot, entry);
        emit_discovery("Process32NextW", result && entry != nullptr ? mrtw::narrow(entry->szExeFile) : "", 0, result && entry != nullptr ? entry->th32ProcessID : 0, result);
        return result;
    }

    HANDLE WINAPI detour_FindFirstFileW(LPCWSTR file_name, LPWIN32_FIND_DATAW data)
    {
        if (mrtw::hook_guard) return real_FindFirstFileW(file_name, data);
        mrtw::HookGuard guard;
        HANDLE result = real_FindFirstFileW(file_name, data);
        emit_discovery("FindFirstFileW", mrtw::narrow(file_name), 0, 0, result != INVALID_HANDLE_VALUE);
        return result;
    }

    BOOL WINAPI detour_FindNextFileW(HANDLE find_file, LPWIN32_FIND_DATAW data)
    {
        if (mrtw::hook_guard) return real_FindNextFileW(find_file, data);
        mrtw::HookGuard guard;
        BOOL result = real_FindNextFileW(find_file, data);
        emit_discovery("FindNextFileW", result && data != nullptr ? mrtw::narrow(data->cFileName) : "", 0, 0, result);
        return result;
    }

    LSTATUS WINAPI detour_RegEnumKeyExW(HKEY key, DWORD index, LPWSTR name, LPDWORD name_size, LPDWORD reserved, LPWSTR class_name, LPDWORD class_size, PFILETIME last_write)
    {
        if (mrtw::hook_guard) return real_RegEnumKeyExW(key, index, name, name_size, reserved, class_name, class_size, last_write);
        mrtw::HookGuard guard;
        LSTATUS status = real_RegEnumKeyExW(key, index, name, name_size, reserved, class_name, class_size, last_write);
        emit_discovery("RegEnumKeyExW", status == ERROR_SUCCESS && name != nullptr ? mrtw::narrow(name) : "", index, 0, status == ERROR_SUCCESS);
        return status;
    }

    LSTATUS WINAPI detour_RegEnumValueW(HKEY key, DWORD index, LPWSTR value_name, LPDWORD value_name_size, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD data_size)
    {
        if (mrtw::hook_guard) return real_RegEnumValueW(key, index, value_name, value_name_size, reserved, type, data, data_size);
        mrtw::HookGuard guard;
        LSTATUS status = real_RegEnumValueW(key, index, value_name, value_name_size, reserved, type, data, data_size);
        emit_discovery("RegEnumValueW", status == ERROR_SUCCESS && value_name != nullptr ? mrtw::narrow(value_name) : "", index, 0, status == ERROR_SUCCESS);
        return status;
    }

    BOOL WINAPI detour_EnumProcesses(DWORD* process_ids, DWORD bytes, DWORD* bytes_returned)
    {
        if (mrtw::hook_guard) return real_EnumProcesses(process_ids, bytes, bytes_returned);
        mrtw::HookGuard guard;
        BOOL result = real_EnumProcesses(process_ids, bytes, bytes_returned);
        emit_discovery("EnumProcesses", "process list", bytes, 0, result);
        return result;
    }
}

namespace mrtw
{
    bool install_discovery_hooks()
    {
        LoadLibraryW(L"advapi32.dll");
        LoadLibraryW(L"psapi.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateToolhelp32Snapshot", reinterpret_cast<LPVOID>(&detour_CreateToolhelp32Snapshot), reinterpret_cast<LPVOID*>(&real_CreateToolhelp32Snapshot)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "Process32FirstW", reinterpret_cast<LPVOID>(&detour_Process32FirstW), reinterpret_cast<LPVOID*>(&real_Process32FirstW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "Process32NextW", reinterpret_cast<LPVOID>(&detour_Process32NextW), reinterpret_cast<LPVOID*>(&real_Process32NextW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "FindFirstFileW", reinterpret_cast<LPVOID>(&detour_FindFirstFileW), reinterpret_cast<LPVOID*>(&real_FindFirstFileW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "FindNextFileW", reinterpret_cast<LPVOID>(&detour_FindNextFileW), reinterpret_cast<LPVOID*>(&real_FindNextFileW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegEnumKeyExW", reinterpret_cast<LPVOID>(&detour_RegEnumKeyExW), reinterpret_cast<LPVOID*>(&real_RegEnumKeyExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegEnumValueW", reinterpret_cast<LPVOID>(&detour_RegEnumValueW), reinterpret_cast<LPVOID*>(&real_RegEnumValueW)) == MH_OK;
        ok &= MH_CreateHookApi(L"psapi.dll", "EnumProcesses", reinterpret_cast<LPVOID>(&detour_EnumProcesses), reinterpret_cast<LPVOID*>(&real_EnumProcesses)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"discovery_hooks_installed"})" : R"({"source":"hook","event":"discovery_hooks_failed"})");
        return ok;
    }
}
