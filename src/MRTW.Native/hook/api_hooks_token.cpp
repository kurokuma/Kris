#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <shellapi.h>

#include <sstream>

namespace
{
    using OpenProcessTokenFn = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
    using AdjustTokenPrivilegesFn = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    using DuplicateTokenExFn = BOOL(WINAPI*)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
    using ImpersonateLoggedOnUserFn = BOOL(WINAPI*)(HANDLE);
    using ShellExecuteWFn = HINSTANCE(WINAPI*)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
    using ShellExecuteAFn = HINSTANCE(WINAPI*)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
    using ShellExecuteExWFn = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
    using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);

    OpenProcessTokenFn real_OpenProcessToken = nullptr;
    AdjustTokenPrivilegesFn real_AdjustTokenPrivileges = nullptr;
    DuplicateTokenExFn real_DuplicateTokenEx = nullptr;
    ImpersonateLoggedOnUserFn real_ImpersonateLoggedOnUser = nullptr;
    ShellExecuteWFn real_ShellExecuteW = nullptr;
    ShellExecuteAFn real_ShellExecuteA = nullptr;
    ShellExecuteExWFn real_ShellExecuteExW = nullptr;
    TerminateProcessFn real_TerminateProcess = nullptr;

    BOOL WINAPI detour_OpenProcessToken(HANDLE process, DWORD desired_access, PHANDLE token)
    {
        if (mrtw::hook_guard) return real_OpenProcessToken(process, desired_access, token);
        mrtw::HookGuard guard;
        BOOL result = real_OpenProcessToken(process, desired_access, token);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"OpenProcessToken","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"desired_access":)" << desired_access
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_AdjustTokenPrivileges(HANDLE token, BOOL disable_all, PTOKEN_PRIVILEGES new_state, DWORD buffer_length, PTOKEN_PRIVILEGES previous_state, PDWORD return_length)
    {
        if (mrtw::hook_guard) return real_AdjustTokenPrivileges(token, disable_all, new_state, buffer_length, previous_state, return_length);
        mrtw::HookGuard guard;
        BOOL result = real_AdjustTokenPrivileges(token, disable_all, new_state, buffer_length, previous_state, return_length);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"AdjustTokenPrivileges","pid":)" << mrtw::current_pid()
             << R"(,"privilege_count":)" << (new_state == nullptr ? 0 : new_state->PrivilegeCount)
             << R"(,"disable_all":)" << (disable_all ? "true" : "false")
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_DuplicateTokenEx(HANDLE existing_token, DWORD desired_access, LPSECURITY_ATTRIBUTES attributes, SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, PHANDLE new_token)
    {
        if (mrtw::hook_guard) return real_DuplicateTokenEx(existing_token, desired_access, attributes, level, type, new_token);
        mrtw::HookGuard guard;
        BOOL result = real_DuplicateTokenEx(existing_token, desired_access, attributes, level, type, new_token);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"DuplicateTokenEx","pid":)" << mrtw::current_pid()
             << R"(,"desired_access":)" << desired_access
             << R"(,"impersonation_level":)" << static_cast<int>(level)
             << R"(,"token_type":)" << static_cast<int>(type)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_ImpersonateLoggedOnUser(HANDLE token)
    {
        if (mrtw::hook_guard) return real_ImpersonateLoggedOnUser(token);
        mrtw::HookGuard guard;
        BOOL result = real_ImpersonateLoggedOnUser(token);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"ImpersonateLoggedOnUser","pid":)" << mrtw::current_pid()
             << R"(,"token":)" << reinterpret_cast<uintptr_t>(token)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HINSTANCE WINAPI detour_ShellExecuteW(HWND window, LPCWSTR operation, LPCWSTR file, LPCWSTR parameters, LPCWSTR directory, INT show_command)
    {
        if (mrtw::hook_guard) return real_ShellExecuteW(window, operation, file, parameters, directory, show_command);
        std::string verb = mrtw::narrow(operation);
        std::string target = mrtw::narrow(file);
        std::string args = mrtw::narrow(parameters);
        std::string working_directory = mrtw::narrow(directory);
        mrtw::HookGuard guard;
        HINSTANCE result = real_ShellExecuteW(window, operation, file, parameters, directory, show_command);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"ShellExecuteW","pid":)" << mrtw::current_pid()
             << R"(,"verb":)" << mrtw::q(verb)
             << R"(,"file":)" << mrtw::q(target)
             << R"(,"parameters":)" << mrtw::q(args)
             << R"(,"directory":)" << mrtw::q(working_directory)
             << R"(,"show_command":)" << show_command
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HINSTANCE WINAPI detour_ShellExecuteA(HWND window, LPCSTR operation, LPCSTR file, LPCSTR parameters, LPCSTR directory, INT show_command)
    {
        if (mrtw::hook_guard) return real_ShellExecuteA(window, operation, file, parameters, directory, show_command);
        std::string verb = operation == nullptr ? std::string{} : std::string(operation);
        std::string target = file == nullptr ? std::string{} : std::string(file);
        std::string args = parameters == nullptr ? std::string{} : std::string(parameters);
        std::string working_directory = directory == nullptr ? std::string{} : std::string(directory);
        mrtw::HookGuard guard;
        HINSTANCE result = real_ShellExecuteA(window, operation, file, parameters, directory, show_command);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"ShellExecuteA","pid":)" << mrtw::current_pid()
             << R"(,"verb":)" << mrtw::q(verb)
             << R"(,"file":)" << mrtw::q(target)
             << R"(,"parameters":)" << mrtw::q(args)
             << R"(,"directory":)" << mrtw::q(working_directory)
             << R"(,"show_command":)" << show_command
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_ShellExecuteExW(SHELLEXECUTEINFOW* info)
    {
        if (mrtw::hook_guard) return real_ShellExecuteExW(info);
        std::string verb = info == nullptr ? std::string{} : mrtw::narrow(info->lpVerb);
        std::string file = info == nullptr ? std::string{} : mrtw::narrow(info->lpFile);
        std::string parameters = info == nullptr ? std::string{} : mrtw::narrow(info->lpParameters);
        mrtw::HookGuard guard;
        BOOL result = real_ShellExecuteExW(info);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"ShellExecuteExW","pid":)" << mrtw::current_pid()
             << R"(,"verb":)" << mrtw::q(verb)
             << R"(,"file":)" << mrtw::q(file)
             << R"(,"parameters":)" << mrtw::q(parameters)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_TerminateProcess(HANDLE process, UINT exit_code)
    {
        if (mrtw::hook_guard) return real_TerminateProcess(process, exit_code);
        mrtw::HookGuard guard;
        BOOL result = real_TerminateProcess(process, exit_code);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"TerminateProcess","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"exit_code":)" << exit_code
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_token_hooks()
    {
        LoadLibraryW(L"advapi32.dll");
        LoadLibraryW(L"shell32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"advapi32.dll", "OpenProcessToken", reinterpret_cast<LPVOID>(&detour_OpenProcessToken), reinterpret_cast<LPVOID*>(&real_OpenProcessToken)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "AdjustTokenPrivileges", reinterpret_cast<LPVOID>(&detour_AdjustTokenPrivileges), reinterpret_cast<LPVOID*>(&real_AdjustTokenPrivileges)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "DuplicateTokenEx", reinterpret_cast<LPVOID>(&detour_DuplicateTokenEx), reinterpret_cast<LPVOID*>(&real_DuplicateTokenEx)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "ImpersonateLoggedOnUser", reinterpret_cast<LPVOID>(&detour_ImpersonateLoggedOnUser), reinterpret_cast<LPVOID*>(&real_ImpersonateLoggedOnUser)) == MH_OK;
        ok &= MH_CreateHookApi(L"shell32.dll", "ShellExecuteW", reinterpret_cast<LPVOID>(&detour_ShellExecuteW), reinterpret_cast<LPVOID*>(&real_ShellExecuteW)) == MH_OK;
        ok &= MH_CreateHookApi(L"shell32.dll", "ShellExecuteA", reinterpret_cast<LPVOID>(&detour_ShellExecuteA), reinterpret_cast<LPVOID*>(&real_ShellExecuteA)) == MH_OK;
        ok &= MH_CreateHookApi(L"shell32.dll", "ShellExecuteExW", reinterpret_cast<LPVOID>(&detour_ShellExecuteExW), reinterpret_cast<LPVOID*>(&real_ShellExecuteExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "TerminateProcess", reinterpret_cast<LPVOID>(&detour_TerminateProcess), reinterpret_cast<LPVOID*>(&real_TerminateProcess)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"token_hooks_installed"})" : R"({"source":"hook","event":"token_hooks_failed"})");
        return ok;
    }
}
