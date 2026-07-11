#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using CreateMutexWFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
    using OpenMutexWFn = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
    using CreateNamedPipeWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
    using ConnectNamedPipeFn = BOOL(WINAPI*)(HANDLE, LPOVERLAPPED);
    using CallNamedPipeWFn = BOOL(WINAPI*)(LPCWSTR, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, DWORD);
    using CreateFileMappingWFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    using MapViewOfFileFn = LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);

    CreateMutexWFn real_CreateMutexW = nullptr;
    OpenMutexWFn real_OpenMutexW = nullptr;
    CreateNamedPipeWFn real_CreateNamedPipeW = nullptr;
    ConnectNamedPipeFn real_ConnectNamedPipe = nullptr;
    CallNamedPipeWFn real_CallNamedPipeW = nullptr;
    CreateFileMappingWFn real_CreateFileMappingW = nullptr;
    MapViewOfFileFn real_MapViewOfFile = nullptr;

    HANDLE WINAPI detour_CreateMutexW(LPSECURITY_ATTRIBUTES attributes, BOOL initial_owner, LPCWSTR name)
    {
        if (mrtw::hook_guard) return real_CreateMutexW(attributes, initial_owner, name);
        std::string mutex = mrtw::narrow(name);
        mrtw::HookGuard guard;
        HANDLE result = real_CreateMutexW(attributes, initial_owner, name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CreateMutexW","pid":)" << mrtw::current_pid()
             << R"(,"mutex_name":)" << mrtw::q(mutex)
             << R"(,"initial_owner":)" << (initial_owner ? "true" : "false")
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HANDLE WINAPI detour_OpenMutexW(DWORD desired_access, BOOL inherit_handle, LPCWSTR name)
    {
        if (mrtw::hook_guard) return real_OpenMutexW(desired_access, inherit_handle, name);
        std::string mutex = mrtw::narrow(name);
        mrtw::HookGuard guard;
        HANDLE result = real_OpenMutexW(desired_access, inherit_handle, name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"OpenMutexW","pid":)" << mrtw::current_pid()
             << R"(,"mutex_name":)" << mrtw::q(mutex)
             << R"(,"desired_access":)" << desired_access
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HANDLE WINAPI detour_CreateNamedPipeW(LPCWSTR name, DWORD open_mode, DWORD pipe_mode, DWORD max_instances, DWORD out_buffer_size, DWORD in_buffer_size, DWORD timeout, LPSECURITY_ATTRIBUTES attributes)
    {
        if (mrtw::hook_guard) return real_CreateNamedPipeW(name, open_mode, pipe_mode, max_instances, out_buffer_size, in_buffer_size, timeout, attributes);
        std::string pipe = mrtw::narrow(name);
        mrtw::HookGuard guard;
        HANDLE result = real_CreateNamedPipeW(name, open_mode, pipe_mode, max_instances, out_buffer_size, in_buffer_size, timeout, attributes);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CreateNamedPipeW","pid":)" << mrtw::current_pid()
             << R"(,"pipe_name":)" << mrtw::q(pipe)
             << R"(,"open_mode":)" << open_mode
             << R"(,"pipe_mode":)" << pipe_mode
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_ConnectNamedPipe(HANDLE pipe, LPOVERLAPPED overlapped)
    {
        if (mrtw::hook_guard) return real_ConnectNamedPipe(pipe, overlapped);
        mrtw::HookGuard guard;
        BOOL result = real_ConnectNamedPipe(pipe, overlapped);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"ConnectNamedPipe","pid":)" << mrtw::current_pid()
             << R"(,"pipe_handle":)" << reinterpret_cast<uintptr_t>(pipe)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CallNamedPipeW(LPCWSTR name, LPVOID in_buffer, DWORD in_buffer_size, LPVOID out_buffer, DWORD out_buffer_size, LPDWORD bytes_read, DWORD timeout)
    {
        if (mrtw::hook_guard) return real_CallNamedPipeW(name, in_buffer, in_buffer_size, out_buffer, out_buffer_size, bytes_read, timeout);
        std::string pipe = mrtw::narrow(name);
        mrtw::HookGuard guard;
        BOOL result = real_CallNamedPipeW(name, in_buffer, in_buffer_size, out_buffer, out_buffer_size, bytes_read, timeout);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CallNamedPipeW","pid":)" << mrtw::current_pid()
             << R"(,"pipe_name":)" << mrtw::q(pipe)
             << R"(,"in_buffer_size":)" << in_buffer_size
             << R"(,"out_buffer_size":)" << out_buffer_size
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HANDLE WINAPI detour_CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES attributes, DWORD protect, DWORD max_size_high, DWORD max_size_low, LPCWSTR name)
    {
        if (mrtw::hook_guard) return real_CreateFileMappingW(file, attributes, protect, max_size_high, max_size_low, name);
        std::string mapping = mrtw::narrow(name);
        mrtw::HookGuard guard;
        HANDLE result = real_CreateFileMappingW(file, attributes, protect, max_size_high, max_size_low, name);
        unsigned long long size = (static_cast<unsigned long long>(max_size_high) << 32) | max_size_low;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CreateFileMappingW","pid":)" << mrtw::current_pid()
             << R"(,"mapping_name":)" << mrtw::q(mapping)
             << R"(,"protect":)" << protect
             << R"(,"size":)" << size
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    LPVOID WINAPI detour_MapViewOfFile(HANDLE mapping, DWORD desired_access, DWORD offset_high, DWORD offset_low, SIZE_T bytes_to_map)
    {
        if (mrtw::hook_guard) return real_MapViewOfFile(mapping, desired_access, offset_high, offset_low, bytes_to_map);
        mrtw::HookGuard guard;
        LPVOID result = real_MapViewOfFile(mapping, desired_access, offset_high, offset_low, bytes_to_map);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"MapViewOfFile","pid":)" << mrtw::current_pid()
             << R"(,"desired_access":)" << desired_access
             << R"(,"bytes_to_map":)" << static_cast<unsigned long long>(bytes_to_map)
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_ipc_hooks()
    {
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateMutexW", reinterpret_cast<LPVOID>(&detour_CreateMutexW), reinterpret_cast<LPVOID*>(&real_CreateMutexW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "OpenMutexW", reinterpret_cast<LPVOID>(&detour_OpenMutexW), reinterpret_cast<LPVOID*>(&real_OpenMutexW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateNamedPipeW", reinterpret_cast<LPVOID>(&detour_CreateNamedPipeW), reinterpret_cast<LPVOID*>(&real_CreateNamedPipeW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "ConnectNamedPipe", reinterpret_cast<LPVOID>(&detour_ConnectNamedPipe), reinterpret_cast<LPVOID*>(&real_ConnectNamedPipe)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CallNamedPipeW", reinterpret_cast<LPVOID>(&detour_CallNamedPipeW), reinterpret_cast<LPVOID*>(&real_CallNamedPipeW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateFileMappingW", reinterpret_cast<LPVOID>(&detour_CreateFileMappingW), reinterpret_cast<LPVOID*>(&real_CreateFileMappingW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "MapViewOfFile", reinterpret_cast<LPVOID>(&detour_MapViewOfFile), reinterpret_cast<LPVOID*>(&real_MapViewOfFile)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"ipc_hooks_installed"})" : R"({"source":"hook","event":"ipc_hooks_failed"})");
        return ok;
    }
}
