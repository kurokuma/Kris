#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <winternl.h>

#include <sstream>

namespace
{
    using IsDebuggerPresentFn = BOOL(WINAPI*)();
    using CheckRemoteDebuggerPresentFn = BOOL(WINAPI*)(HANDLE, PBOOL);
    using SleepFn = VOID(WINAPI*)(DWORD);
    using SleepExFn = DWORD(WINAPI*)(DWORD, BOOL);
    using GetTickCountFn = DWORD(WINAPI*)();
    using QueryPerformanceCounterFn = BOOL(WINAPI*)(LARGE_INTEGER*);
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    IsDebuggerPresentFn real_IsDebuggerPresent = nullptr;
    CheckRemoteDebuggerPresentFn real_CheckRemoteDebuggerPresent = nullptr;
    SleepFn real_Sleep = nullptr;
    SleepExFn real_SleepEx = nullptr;
    GetTickCountFn real_GetTickCount = nullptr;
    QueryPerformanceCounterFn real_QueryPerformanceCounter = nullptr;
    NtQueryInformationProcessFn real_NtQueryInformationProcess = nullptr;

    BOOL WINAPI detour_IsDebuggerPresent()
    {
        if (mrtw::hook_guard)
        {
            return real_IsDebuggerPresent();
        }
        mrtw::HookGuard guard;
        BOOL result = real_IsDebuggerPresent();
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"IsDebuggerPresent","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << (result ? "true" : "false") << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CheckRemoteDebuggerPresent(HANDLE process, PBOOL debugger_present)
    {
        if (mrtw::hook_guard)
        {
            return real_CheckRemoteDebuggerPresent(process, debugger_present);
        }
        mrtw::HookGuard guard;
        BOOL result = real_CheckRemoteDebuggerPresent(process, debugger_present);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CheckRemoteDebuggerPresent","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"debugger_present":)" << (debugger_present == nullptr ? "false" : (*debugger_present ? "true" : "false"))
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    VOID WINAPI detour_Sleep(DWORD milliseconds)
    {
        if (mrtw::hook_guard)
        {
            real_Sleep(milliseconds);
            return;
        }
        mrtw::HookGuard guard;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"Sleep","pid":)" << mrtw::current_pid()
             << R"(,"milliseconds":)" << milliseconds << "}";
        mrtw::emit_event(json.str());
        real_Sleep(milliseconds);
    }

    DWORD WINAPI detour_SleepEx(DWORD milliseconds, BOOL alertable)
    {
        if (mrtw::hook_guard)
        {
            return real_SleepEx(milliseconds, alertable);
        }
        mrtw::HookGuard guard;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"SleepEx","pid":)" << mrtw::current_pid()
             << R"(,"milliseconds":)" << milliseconds
             << R"(,"alertable":)" << (alertable ? "true" : "false")
             << "}";
        mrtw::emit_event(json.str());
        return real_SleepEx(milliseconds, alertable);
    }

    DWORD WINAPI detour_GetTickCount()
    {
        if (mrtw::hook_guard)
        {
            return real_GetTickCount();
        }
        mrtw::HookGuard guard;
        DWORD result = real_GetTickCount();
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetTickCount","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << result << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_QueryPerformanceCounter(LARGE_INTEGER* counter)
    {
        if (mrtw::hook_guard)
        {
            return real_QueryPerformanceCounter(counter);
        }
        mrtw::HookGuard guard;
        BOOL result = real_QueryPerformanceCounter(counter);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"QueryPerformanceCounter","pid":)" << mrtw::current_pid()
             << R"(,"result":)" << (result ? "true" : "false") << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    NTSTATUS NTAPI detour_NtQueryInformationProcess(HANDLE process, PROCESSINFOCLASS information_class, PVOID information, ULONG information_length, PULONG return_length)
    {
        if (mrtw::hook_guard)
        {
            return real_NtQueryInformationProcess(process, information_class, information, information_length, return_length);
        }
        mrtw::HookGuard guard;
        NTSTATUS status = real_NtQueryInformationProcess(process, information_class, information, information_length, return_length);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"NtQueryInformationProcess","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"information_class":)" << static_cast<int>(information_class)
             << R"(,"status":)" << status
             << "}";
        mrtw::emit_event(json.str());
        return status;
    }
}

namespace mrtw
{
    bool install_anti_analysis_hooks()
    {
        LoadLibraryW(L"ntdll.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "IsDebuggerPresent", reinterpret_cast<LPVOID>(&detour_IsDebuggerPresent), reinterpret_cast<LPVOID*>(&real_IsDebuggerPresent)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CheckRemoteDebuggerPresent", reinterpret_cast<LPVOID>(&detour_CheckRemoteDebuggerPresent), reinterpret_cast<LPVOID*>(&real_CheckRemoteDebuggerPresent)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "Sleep", reinterpret_cast<LPVOID>(&detour_Sleep), reinterpret_cast<LPVOID*>(&real_Sleep)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "SleepEx", reinterpret_cast<LPVOID>(&detour_SleepEx), reinterpret_cast<LPVOID*>(&real_SleepEx)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "GetTickCount", reinterpret_cast<LPVOID>(&detour_GetTickCount), reinterpret_cast<LPVOID*>(&real_GetTickCount)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "QueryPerformanceCounter", reinterpret_cast<LPVOID>(&detour_QueryPerformanceCounter), reinterpret_cast<LPVOID*>(&real_QueryPerformanceCounter)) == MH_OK;
        ok &= MH_CreateHookApi(L"ntdll.dll", "NtQueryInformationProcess", reinterpret_cast<LPVOID>(&detour_NtQueryInformationProcess), reinterpret_cast<LPVOID*>(&real_NtQueryInformationProcess)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"anti_analysis_hooks_installed"})" : R"({"source":"hook","event":"anti_analysis_hooks_failed"})");
        return ok;
    }
}
