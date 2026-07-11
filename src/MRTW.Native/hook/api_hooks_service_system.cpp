#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <winternl.h>

#include <sstream>

namespace
{
    using OpenSCManagerWFn = SC_HANDLE(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
    using OpenServiceWFn = SC_HANDLE(WINAPI*)(SC_HANDLE, LPCWSTR, DWORD);
    using StartServiceWFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPCWSTR*);
    using ControlServiceFn = BOOL(WINAPI*)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
    using DeleteServiceFn = BOOL(WINAPI*)(SC_HANDLE);
    using EnumServicesStatusExWFn = BOOL(WINAPI*)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
    using NtLoadDriverFn = NTSTATUS(NTAPI*)(PUNICODE_STRING);

    OpenSCManagerWFn real_OpenSCManagerW = nullptr;
    OpenServiceWFn real_OpenServiceW = nullptr;
    StartServiceWFn real_StartServiceW = nullptr;
    ControlServiceFn real_ControlService = nullptr;
    DeleteServiceFn real_DeleteService = nullptr;
    EnumServicesStatusExWFn real_EnumServicesStatusExW = nullptr;
    NtLoadDriverFn real_NtLoadDriver = nullptr;

    void emit_handle_action(const char* action, const std::string& object, uintptr_t result, DWORD last_error)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":)" << mrtw::q(action)
             << R"(,"pid":)" << mrtw::current_pid()
             << R"(,"object":)" << mrtw::q(object)
             << R"(,"result":)" << result
             << R"(,"last_error":)" << last_error << "}";
        mrtw::emit_event(json.str());
    }

    SC_HANDLE WINAPI detour_OpenSCManagerW(LPCWSTR machine, LPCWSTR database, DWORD desired_access)
    {
        if (mrtw::hook_guard) return real_OpenSCManagerW(machine, database, desired_access);
        std::string object = mrtw::narrow(machine) + "\\" + mrtw::narrow(database);
        mrtw::HookGuard guard;
        SC_HANDLE result = real_OpenSCManagerW(machine, database, desired_access);
        emit_handle_action("OpenSCManagerW", object, reinterpret_cast<uintptr_t>(result), GetLastError());
        return result;
    }

    SC_HANDLE WINAPI detour_OpenServiceW(SC_HANDLE manager, LPCWSTR service_name, DWORD desired_access)
    {
        if (mrtw::hook_guard) return real_OpenServiceW(manager, service_name, desired_access);
        std::string service = mrtw::narrow(service_name);
        mrtw::HookGuard guard;
        SC_HANDLE result = real_OpenServiceW(manager, service_name, desired_access);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"OpenServiceW","pid":)" << mrtw::current_pid()
             << R"(,"service_name":)" << mrtw::q(service)
             << R"(,"desired_access":)" << desired_access
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_StartServiceW(SC_HANDLE service, DWORD argc, LPCWSTR* argv)
    {
        if (mrtw::hook_guard) return real_StartServiceW(service, argc, argv);
        mrtw::HookGuard guard;
        BOOL result = real_StartServiceW(service, argc, argv);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"StartServiceW","pid":)" << mrtw::current_pid()
             << R"(,"argument_count":)" << argc
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_ControlService(SC_HANDLE service, DWORD control, LPSERVICE_STATUS status)
    {
        if (mrtw::hook_guard) return real_ControlService(service, control, status);
        mrtw::HookGuard guard;
        BOOL result = real_ControlService(service, control, status);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"ControlService","pid":)" << mrtw::current_pid()
             << R"(,"control":)" << control
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_DeleteService(SC_HANDLE service)
    {
        if (mrtw::hook_guard) return real_DeleteService(service);
        mrtw::HookGuard guard;
        BOOL result = real_DeleteService(service);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"DeleteService","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_EnumServicesStatusExW(SC_HANDLE manager, SC_ENUM_TYPE info_level, DWORD service_type, DWORD service_state, LPBYTE services, DWORD buffer_size, LPDWORD bytes_needed, LPDWORD services_returned, LPDWORD resume_handle, LPCWSTR group)
    {
        if (mrtw::hook_guard) return real_EnumServicesStatusExW(manager, info_level, service_type, service_state, services, buffer_size, bytes_needed, services_returned, resume_handle, group);
        mrtw::HookGuard guard;
        BOOL result = real_EnumServicesStatusExW(manager, info_level, service_type, service_state, services, buffer_size, bytes_needed, services_returned, resume_handle, group);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"EnumServicesStatusExW","pid":)" << mrtw::current_pid()
             << R"(,"service_type":)" << service_type
             << R"(,"service_state":)" << service_state
             << R"(,"services_returned":)" << (services_returned == nullptr ? 0 : *services_returned)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    NTSTATUS NTAPI detour_NtLoadDriver(PUNICODE_STRING driver_service_name)
    {
        if (mrtw::hook_guard) return real_NtLoadDriver(driver_service_name);
        std::wstring value;
        if (driver_service_name != nullptr && driver_service_name->Buffer != nullptr)
        {
            value.assign(driver_service_name->Buffer, driver_service_name->Length / sizeof(wchar_t));
        }

        mrtw::HookGuard guard;
        NTSTATUS status = real_NtLoadDriver(driver_service_name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"NtLoadDriver","pid":)" << mrtw::current_pid()
             << R"(,"driver_service":)" << mrtw::q(mrtw::narrow(value))
             << R"(,"status":)" << status << "}";
        mrtw::emit_event(json.str());
        return status;
    }
}

namespace mrtw
{
    bool install_service_system_hooks()
    {
        LoadLibraryW(L"advapi32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"advapi32.dll", "OpenSCManagerW", reinterpret_cast<LPVOID>(&detour_OpenSCManagerW), reinterpret_cast<LPVOID*>(&real_OpenSCManagerW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "OpenServiceW", reinterpret_cast<LPVOID>(&detour_OpenServiceW), reinterpret_cast<LPVOID*>(&real_OpenServiceW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "StartServiceW", reinterpret_cast<LPVOID>(&detour_StartServiceW), reinterpret_cast<LPVOID*>(&real_StartServiceW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "ControlService", reinterpret_cast<LPVOID>(&detour_ControlService), reinterpret_cast<LPVOID*>(&real_ControlService)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "DeleteService", reinterpret_cast<LPVOID>(&detour_DeleteService), reinterpret_cast<LPVOID*>(&real_DeleteService)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "EnumServicesStatusExW", reinterpret_cast<LPVOID>(&detour_EnumServicesStatusExW), reinterpret_cast<LPVOID*>(&real_EnumServicesStatusExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"ntdll.dll", "NtLoadDriver", reinterpret_cast<LPVOID>(&detour_NtLoadDriver), reinterpret_cast<LPVOID*>(&real_NtLoadDriver)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"service_system_hooks_installed"})" : R"({"source":"hook","event":"service_system_hooks_failed"})");
        return ok;
    }
}
