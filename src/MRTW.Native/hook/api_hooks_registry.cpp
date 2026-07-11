#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using RegCreateKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    using RegOpenKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    using RegSetValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    using RegSetKeyValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD);
    using RegDeleteValueWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
    using RegDeleteKeyWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
    using CreateServiceWFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
    using ChangeServiceConfigWFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);

    RegCreateKeyExWFn real_RegCreateKeyExW = nullptr;
    RegOpenKeyExWFn real_RegOpenKeyExW = nullptr;
    RegSetValueExWFn real_RegSetValueExW = nullptr;
    RegSetKeyValueWFn real_RegSetKeyValueW = nullptr;
    RegDeleteValueWFn real_RegDeleteValueW = nullptr;
    RegDeleteKeyWFn real_RegDeleteKeyW = nullptr;
    CreateServiceWFn real_CreateServiceW = nullptr;
    ChangeServiceConfigWFn real_ChangeServiceConfigW = nullptr;

    void emit_registry(const char* action, HKEY key, LPCWSTR sub_key, LPCWSTR value_name, LSTATUS status)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"Registry","action":)" << mrtw::q(action)
             << R"(,"pid":)" << mrtw::current_pid()
             << R"(,"hkey":)" << reinterpret_cast<uintptr_t>(key)
             << R"(,"sub_key":)" << mrtw::q(mrtw::narrow(sub_key))
             << R"(,"value_name":)" << mrtw::q(mrtw::narrow(value_name))
             << R"(,"status":)" << status
             << "}";
        mrtw::emit_event(json.str());
    }

    LSTATUS WINAPI detour_RegCreateKeyExW(HKEY key, LPCWSTR sub_key, DWORD reserved, LPWSTR class_name, DWORD options, REGSAM sam_desired, const LPSECURITY_ATTRIBUTES security, PHKEY result_key, LPDWORD disposition)
    {
        if (mrtw::hook_guard)
        {
            return real_RegCreateKeyExW(key, sub_key, reserved, class_name, options, sam_desired, security, result_key, disposition);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegCreateKeyExW(key, sub_key, reserved, class_name, options, sam_desired, security, result_key, disposition);
        emit_registry("RegCreateKeyExW", key, sub_key, nullptr, status);
        return status;
    }

    LSTATUS WINAPI detour_RegOpenKeyExW(HKEY key, LPCWSTR sub_key, DWORD options, REGSAM sam_desired, PHKEY result_key)
    {
        if (mrtw::hook_guard)
        {
            return real_RegOpenKeyExW(key, sub_key, options, sam_desired, result_key);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegOpenKeyExW(key, sub_key, options, sam_desired, result_key);
        emit_registry("RegOpenKeyExW", key, sub_key, nullptr, status);
        return status;
    }

    LSTATUS WINAPI detour_RegSetValueExW(HKEY key, LPCWSTR value_name, DWORD reserved, DWORD type, const BYTE* data, DWORD data_size)
    {
        if (mrtw::hook_guard)
        {
            return real_RegSetValueExW(key, value_name, reserved, type, data, data_size);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegSetValueExW(key, value_name, reserved, type, data, data_size);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Registry","action":"RegSetValueExW","pid":)" << mrtw::current_pid()
             << R"(,"hkey":)" << reinterpret_cast<uintptr_t>(key)
             << R"(,"value_name":)" << mrtw::q(mrtw::narrow(value_name))
             << R"(,"type":)" << type
             << R"(,"data_size":)" << data_size
             << R"(,"status":)" << status
             << "}";
        mrtw::emit_event(json.str());
        return status;
    }

    LSTATUS WINAPI detour_RegSetKeyValueW(HKEY key, LPCWSTR sub_key, LPCWSTR value_name, DWORD type, LPCVOID data, DWORD data_size)
    {
        if (mrtw::hook_guard)
        {
            return real_RegSetKeyValueW(key, sub_key, value_name, type, data, data_size);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegSetKeyValueW(key, sub_key, value_name, type, data, data_size);
        emit_registry("RegSetKeyValueW", key, sub_key, value_name, status);
        return status;
    }

    LSTATUS WINAPI detour_RegDeleteValueW(HKEY key, LPCWSTR value_name)
    {
        if (mrtw::hook_guard)
        {
            return real_RegDeleteValueW(key, value_name);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegDeleteValueW(key, value_name);
        emit_registry("RegDeleteValueW", key, nullptr, value_name, status);
        return status;
    }

    LSTATUS WINAPI detour_RegDeleteKeyW(HKEY key, LPCWSTR sub_key)
    {
        if (mrtw::hook_guard)
        {
            return real_RegDeleteKeyW(key, sub_key);
        }
        mrtw::HookGuard guard;
        LSTATUS status = real_RegDeleteKeyW(key, sub_key);
        emit_registry("RegDeleteKeyW", key, sub_key, nullptr, status);
        return status;
    }

    SC_HANDLE WINAPI detour_CreateServiceW(SC_HANDLE manager, LPCWSTR service_name, LPCWSTR display_name, DWORD desired_access, DWORD service_type, DWORD start_type, DWORD error_control, LPCWSTR binary_path_name, LPCWSTR load_order_group, LPDWORD tag_id, LPCWSTR dependencies, LPCWSTR service_start_name, LPCWSTR password)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateServiceW(manager, service_name, display_name, desired_access, service_type, start_type, error_control, binary_path_name, load_order_group, tag_id, dependencies, service_start_name, password);
        }
        mrtw::HookGuard guard;
        SC_HANDLE result = real_CreateServiceW(manager, service_name, display_name, desired_access, service_type, start_type, error_control, binary_path_name, load_order_group, tag_id, dependencies, service_start_name, password);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Service","action":"CreateServiceW","pid":)" << mrtw::current_pid()
             << R"(,"service_name":)" << mrtw::q(mrtw::narrow(service_name))
             << R"(,"display_name":)" << mrtw::q(mrtw::narrow(display_name))
             << R"(,"binary_path":)" << mrtw::q(mrtw::narrow(binary_path_name))
             << R"(,"service_type":)" << service_type
             << R"(,"start_type":)" << start_type
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_ChangeServiceConfigW(SC_HANDLE service, DWORD service_type, DWORD start_type, DWORD error_control, LPCWSTR binary_path_name, LPCWSTR load_order_group, LPDWORD tag_id, LPCWSTR dependencies, LPCWSTR service_start_name, LPCWSTR password, LPCWSTR display_name)
    {
        if (mrtw::hook_guard)
        {
            return real_ChangeServiceConfigW(service, service_type, start_type, error_control, binary_path_name, load_order_group, tag_id, dependencies, service_start_name, password, display_name);
        }
        mrtw::HookGuard guard;
        BOOL result = real_ChangeServiceConfigW(service, service_type, start_type, error_control, binary_path_name, load_order_group, tag_id, dependencies, service_start_name, password, display_name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Service","action":"ChangeServiceConfigW","pid":)" << mrtw::current_pid()
             << R"(,"binary_path":)" << mrtw::q(mrtw::narrow(binary_path_name))
             << R"(,"start_type":)" << start_type
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_registry_hooks()
    {
        LoadLibraryW(L"advapi32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegCreateKeyExW", reinterpret_cast<LPVOID>(&detour_RegCreateKeyExW), reinterpret_cast<LPVOID*>(&real_RegCreateKeyExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegOpenKeyExW", reinterpret_cast<LPVOID>(&detour_RegOpenKeyExW), reinterpret_cast<LPVOID*>(&real_RegOpenKeyExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegSetValueExW", reinterpret_cast<LPVOID>(&detour_RegSetValueExW), reinterpret_cast<LPVOID*>(&real_RegSetValueExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegSetKeyValueW", reinterpret_cast<LPVOID>(&detour_RegSetKeyValueW), reinterpret_cast<LPVOID*>(&real_RegSetKeyValueW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegDeleteValueW", reinterpret_cast<LPVOID>(&detour_RegDeleteValueW), reinterpret_cast<LPVOID*>(&real_RegDeleteValueW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "RegDeleteKeyW", reinterpret_cast<LPVOID>(&detour_RegDeleteKeyW), reinterpret_cast<LPVOID*>(&real_RegDeleteKeyW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "CreateServiceW", reinterpret_cast<LPVOID>(&detour_CreateServiceW), reinterpret_cast<LPVOID*>(&real_CreateServiceW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "ChangeServiceConfigW", reinterpret_cast<LPVOID>(&detour_ChangeServiceConfigW), reinterpret_cast<LPVOID*>(&real_ChangeServiceConfigW)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"registry_hooks_installed"})" : R"({"source":"hook","event":"registry_hooks_failed"})");
        return ok;
    }
}
