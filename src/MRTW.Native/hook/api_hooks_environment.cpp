#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <lmcons.h>
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>

#include <sstream>

namespace
{
    using InternetSetOptionWFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
    using WinHttpSetOptionFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
    using GetAdaptersAddressesFn = ULONG(WINAPI*)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
    using GetComputerNameWFn = BOOL(WINAPI*)(LPWSTR, LPDWORD);
    using GetUserNameWFn = BOOL(WINAPI*)(LPWSTR, LPDWORD);
    using GetSystemFirmwareTableFn = UINT(WINAPI*)(DWORD, DWORD, PVOID, DWORD);

    InternetSetOptionWFn real_InternetSetOptionW = nullptr;
    WinHttpSetOptionFn real_WinHttpSetOption = nullptr;
    GetAdaptersAddressesFn real_GetAdaptersAddresses = nullptr;
    GetComputerNameWFn real_GetComputerNameW = nullptr;
    GetUserNameWFn real_GetUserNameW = nullptr;
    GetSystemFirmwareTableFn real_GetSystemFirmwareTable = nullptr;

    BOOL WINAPI detour_InternetSetOptionW(HINTERNET internet, DWORD option, LPVOID buffer, DWORD buffer_length)
    {
        if (mrtw::hook_guard) return real_InternetSetOptionW(internet, option, buffer, buffer_length);
        mrtw::HookGuard guard;
        BOOL result = real_InternetSetOptionW(internet, option, buffer, buffer_length);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"InternetSetOptionW","pid":)" << mrtw::current_pid()
             << R"(,"option":)" << option
             << R"(,"buffer_length":)" << buffer_length
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_WinHttpSetOption(HINTERNET internet, DWORD option, LPVOID buffer, DWORD buffer_length)
    {
        if (mrtw::hook_guard) return real_WinHttpSetOption(internet, option, buffer, buffer_length);
        mrtw::HookGuard guard;
        BOOL result = real_WinHttpSetOption(internet, option, buffer, buffer_length);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WinHttpSetOption","pid":)" << mrtw::current_pid()
             << R"(,"option":)" << option
             << R"(,"buffer_length":)" << buffer_length
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    ULONG WINAPI detour_GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved, PIP_ADAPTER_ADDRESSES addresses, PULONG size_pointer)
    {
        if (mrtw::hook_guard) return real_GetAdaptersAddresses(family, flags, reserved, addresses, size_pointer);
        mrtw::HookGuard guard;
        ULONG result = real_GetAdaptersAddresses(family, flags, reserved, addresses, size_pointer);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetAdaptersAddresses","pid":)" << mrtw::current_pid()
             << R"(,"family":)" << family
             << R"(,"flags":)" << flags
             << R"(,"buffer_size":)" << (size_pointer == nullptr ? 0 : *size_pointer)
             << R"(,"status":)" << result << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_GetComputerNameW(LPWSTR buffer, LPDWORD size)
    {
        if (mrtw::hook_guard) return real_GetComputerNameW(buffer, size);
        mrtw::HookGuard guard;
        BOOL result = real_GetComputerNameW(buffer, size);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetComputerNameW","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"size":)" << (size == nullptr ? 0 : *size)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_GetUserNameW(LPWSTR buffer, LPDWORD size)
    {
        if (mrtw::hook_guard) return real_GetUserNameW(buffer, size);
        mrtw::HookGuard guard;
        BOOL result = real_GetUserNameW(buffer, size);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetUserNameW","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"size":)" << (size == nullptr ? 0 : *size)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    UINT WINAPI detour_GetSystemFirmwareTable(DWORD provider, DWORD table, PVOID buffer, DWORD buffer_size)
    {
        if (mrtw::hook_guard) return real_GetSystemFirmwareTable(provider, table, buffer, buffer_size);
        mrtw::HookGuard guard;
        UINT result = real_GetSystemFirmwareTable(provider, table, buffer, buffer_size);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetSystemFirmwareTable","pid":)" << mrtw::current_pid()
             << R"(,"provider":)" << provider
             << R"(,"table":)" << table
             << R"(,"buffer_size":)" << buffer_size
             << R"(,"result":)" << result << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_environment_hooks()
    {
        LoadLibraryW(L"wininet.dll");
        LoadLibraryW(L"winhttp.dll");
        LoadLibraryW(L"iphlpapi.dll");
        LoadLibraryW(L"advapi32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"wininet.dll", "InternetSetOptionW", reinterpret_cast<LPVOID>(&detour_InternetSetOptionW), reinterpret_cast<LPVOID*>(&real_InternetSetOptionW)) == MH_OK;
        ok &= MH_CreateHookApi(L"winhttp.dll", "WinHttpSetOption", reinterpret_cast<LPVOID>(&detour_WinHttpSetOption), reinterpret_cast<LPVOID*>(&real_WinHttpSetOption)) == MH_OK;
        ok &= MH_CreateHookApi(L"iphlpapi.dll", "GetAdaptersAddresses", reinterpret_cast<LPVOID>(&detour_GetAdaptersAddresses), reinterpret_cast<LPVOID*>(&real_GetAdaptersAddresses)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "GetComputerNameW", reinterpret_cast<LPVOID>(&detour_GetComputerNameW), reinterpret_cast<LPVOID*>(&real_GetComputerNameW)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "GetUserNameW", reinterpret_cast<LPVOID>(&detour_GetUserNameW), reinterpret_cast<LPVOID*>(&real_GetUserNameW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "GetSystemFirmwareTable", reinterpret_cast<LPVOID>(&detour_GetSystemFirmwareTable), reinterpret_cast<LPVOID*>(&real_GetSystemFirmwareTable)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"environment_hooks_installed"})" : R"({"source":"hook","event":"environment_hooks_failed"})");
        return ok;
    }
}
