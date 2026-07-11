#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using CreateProcessAFn = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using VirtualAllocExFn = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using VirtualProtectExFn = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    using WriteProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    using CreateRemoteThreadFn = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using QueueUserAPCFn = DWORD(WINAPI*)(PAPCFUNC, HANDLE, ULONG_PTR);
    using SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const CONTEXT*);
    using ResumeThreadFn = DWORD(WINAPI*)(HANDLE);

    CreateProcessWFn real_CreateProcessW = nullptr;
    CreateProcessAFn real_CreateProcessA = nullptr;
    OpenProcessFn real_OpenProcess = nullptr;
    VirtualAllocExFn real_VirtualAllocEx = nullptr;
    VirtualProtectExFn real_VirtualProtectEx = nullptr;
    WriteProcessMemoryFn real_WriteProcessMemory = nullptr;
    CreateRemoteThreadFn real_CreateRemoteThread = nullptr;
    QueueUserAPCFn real_QueueUserAPC = nullptr;
    SetThreadContextFn real_SetThreadContext = nullptr;
    ResumeThreadFn real_ResumeThread = nullptr;

    bool inject_hook_into_child(HANDLE process)
    {
        std::wstring dll_path = mrtw::hook_module_path();
        if (dll_path.empty() || process == nullptr)
        {
            return false;
        }

        SIZE_T bytes = (dll_path.size() + 1) * sizeof(wchar_t);
        LPVOID remote_memory = real_VirtualAllocEx != nullptr
            ? real_VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            : VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote_memory == nullptr)
        {
            return false;
        }

        SIZE_T written = 0;
        BOOL wrote = real_WriteProcessMemory != nullptr
            ? real_WriteProcessMemory(process, remote_memory, dll_path.c_str(), bytes, &written)
            : WriteProcessMemory(process, remote_memory, dll_path.c_str(), bytes, &written);
        if (!wrote)
        {
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return false;
        }

        auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        if (load_library == nullptr)
        {
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return false;
        }

        HANDLE thread = real_CreateRemoteThread != nullptr
            ? real_CreateRemoteThread(process, nullptr, 0, load_library, remote_memory, 0, nullptr)
            : CreateRemoteThread(process, nullptr, 0, load_library, remote_memory, 0, nullptr);
        if (thread == nullptr)
        {
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
        return true;
    }

    void emit_child_injection(DWORD child_pid, bool injected)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"ChildHookInject","pid":)" << mrtw::current_pid()
             << R"(,"child_pid":)" << child_pid
             << R"(,"result":)" << (injected ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
    }

    BOOL WINAPI detour_CreateProcessW(LPCWSTR application, LPWSTR command_line, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit_handles, DWORD creation_flags, LPVOID environment, LPCWSTR current_directory, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION process_information)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateProcessW(application, command_line, process_attributes, thread_attributes, inherit_handles, creation_flags, environment, current_directory, startup, process_information);
        }

        mrtw::HookGuard guard;
        bool caller_requested_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
        DWORD effective_flags = creation_flags | CREATE_SUSPENDED;
        BOOL result = real_CreateProcessW(application, command_line, process_attributes, thread_attributes, inherit_handles, effective_flags, environment, current_directory, startup, process_information);
        DWORD child_pid = result && process_information != nullptr ? process_information->dwProcessId : 0;
        bool injected = result && process_information != nullptr && inject_hook_into_child(process_information->hProcess);
        if (result && process_information != nullptr && !caller_requested_suspended)
        {
            (real_ResumeThread != nullptr ? real_ResumeThread : ResumeThread)(process_information->hThread);
        }
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"CreateProcessW","pid":)" << mrtw::current_pid()
             << R"(,"application":)" << mrtw::q(mrtw::narrow(application))
             << R"(,"command_line":)" << mrtw::q(mrtw::narrow(command_line))
             << R"(,"current_directory":)" << mrtw::q(mrtw::narrow(current_directory))
             << R"(,"creation_flags":)" << creation_flags
             << R"(,"mrtw_forced_suspended":)" << (!caller_requested_suspended ? "true" : "false")
             << R"(,"child_pid":)" << child_pid
             << R"(,"hook_injected":)" << (injected ? "true" : "false")
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        if (child_pid != 0)
        {
            emit_child_injection(child_pid, injected);
        }
        return result;
    }

    BOOL WINAPI detour_CreateProcessA(LPCSTR application, LPSTR command_line, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit_handles, DWORD creation_flags, LPVOID environment, LPCSTR current_directory, LPSTARTUPINFOA startup, LPPROCESS_INFORMATION process_information)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateProcessA(application, command_line, process_attributes, thread_attributes, inherit_handles, creation_flags, environment, current_directory, startup, process_information);
        }

        mrtw::HookGuard guard;
        bool caller_requested_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
        DWORD effective_flags = creation_flags | CREATE_SUSPENDED;
        BOOL result = real_CreateProcessA(application, command_line, process_attributes, thread_attributes, inherit_handles, effective_flags, environment, current_directory, startup, process_information);
        DWORD child_pid = result && process_information != nullptr ? process_information->dwProcessId : 0;
        bool injected = result && process_information != nullptr && inject_hook_into_child(process_information->hProcess);
        if (result && process_information != nullptr && !caller_requested_suspended)
        {
            (real_ResumeThread != nullptr ? real_ResumeThread : ResumeThread)(process_information->hThread);
        }
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"CreateProcessA","pid":)" << mrtw::current_pid()
             << R"(,"application":)" << mrtw::q(application == nullptr ? std::string{} : std::string(application))
             << R"(,"command_line":)" << mrtw::q(command_line == nullptr ? std::string{} : std::string(command_line))
             << R"(,"current_directory":)" << mrtw::q(current_directory == nullptr ? std::string{} : std::string(current_directory))
             << R"(,"creation_flags":)" << creation_flags
             << R"(,"mrtw_forced_suspended":)" << (!caller_requested_suspended ? "true" : "false")
             << R"(,"child_pid":)" << child_pid
             << R"(,"hook_injected":)" << (injected ? "true" : "false")
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        if (child_pid != 0)
        {
            emit_child_injection(child_pid, injected);
        }
        return result;
    }

    HANDLE WINAPI detour_OpenProcess(DWORD desired_access, BOOL inherit_handle, DWORD process_id)
    {
        if (mrtw::hook_guard)
        {
            return real_OpenProcess(desired_access, inherit_handle, process_id);
        }
        mrtw::HookGuard guard;
        HANDLE result = real_OpenProcess(desired_access, inherit_handle, process_id);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"OpenProcess","pid":)" << mrtw::current_pid()
             << R"(,"target_pid":)" << process_id
             << R"(,"desired_access":)" << desired_access
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    LPVOID WINAPI detour_VirtualAllocEx(HANDLE process, LPVOID address, SIZE_T size, DWORD allocation_type, DWORD protect)
    {
        if (mrtw::hook_guard)
        {
            return real_VirtualAllocEx(process, address, size, allocation_type, protect);
        }
        mrtw::HookGuard guard;
        LPVOID result = real_VirtualAllocEx(process, address, size, allocation_type, protect);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"VirtualAllocEx","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"size":)" << size
             << R"(,"allocation_type":)" << allocation_type
             << R"(,"protect":)" << protect
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_VirtualProtectEx(HANDLE process, LPVOID address, SIZE_T size, DWORD new_protect, PDWORD old_protect)
    {
        if (mrtw::hook_guard)
        {
            return real_VirtualProtectEx(process, address, size, new_protect, old_protect);
        }
        mrtw::HookGuard guard;
        BOOL result = real_VirtualProtectEx(process, address, size, new_protect, old_protect);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"VirtualProtectEx","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"size":)" << size
             << R"(,"new_protect":)" << new_protect
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_WriteProcessMemory(HANDLE process, LPVOID base_address, LPCVOID buffer, SIZE_T size, SIZE_T* written)
    {
        if (mrtw::hook_guard)
        {
            return real_WriteProcessMemory(process, base_address, buffer, size, written);
        }
        mrtw::HookGuard guard;
        BOOL result = real_WriteProcessMemory(process, base_address, buffer, size, written);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"WriteProcessMemory","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"base_address":)" << reinterpret_cast<uintptr_t>(base_address)
             << R"(,"requested_bytes":)" << size
             << R"(,"written_bytes":)" << (written == nullptr ? 0 : *written)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HANDLE WINAPI detour_CreateRemoteThread(HANDLE process, LPSECURITY_ATTRIBUTES attributes, SIZE_T stack_size, LPTHREAD_START_ROUTINE start_address, LPVOID parameter, DWORD creation_flags, LPDWORD thread_id)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateRemoteThread(process, attributes, stack_size, start_address, parameter, creation_flags, thread_id);
        }
        mrtw::HookGuard guard;
        HANDLE result = real_CreateRemoteThread(process, attributes, stack_size, start_address, parameter, creation_flags, thread_id);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"CreateRemoteThread","pid":)" << mrtw::current_pid()
             << R"(,"target_handle":)" << reinterpret_cast<uintptr_t>(process)
             << R"(,"start_address":)" << reinterpret_cast<uintptr_t>(start_address)
             << R"(,"thread_id":)" << (thread_id == nullptr ? 0 : *thread_id)
             << R"(,"creation_flags":)" << creation_flags
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    DWORD WINAPI detour_QueueUserAPC(PAPCFUNC function, HANDLE thread, ULONG_PTR data)
    {
        if (mrtw::hook_guard)
        {
            return real_QueueUserAPC(function, thread, data);
        }
        mrtw::HookGuard guard;
        DWORD result = real_QueueUserAPC(function, thread, data);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"QueueUserAPC","pid":)" << mrtw::current_pid()
             << R"(,"thread_handle":)" << reinterpret_cast<uintptr_t>(thread)
             << R"(,"apc_function":)" << reinterpret_cast<uintptr_t>(function)
             << R"(,"result":)" << result
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_SetThreadContext(HANDLE thread, const CONTEXT* context)
    {
        if (mrtw::hook_guard)
        {
            return real_SetThreadContext(thread, context);
        }
        mrtw::HookGuard guard;
        BOOL result = real_SetThreadContext(thread, context);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"SetThreadContext","pid":)" << mrtw::current_pid()
             << R"(,"thread_handle":)" << reinterpret_cast<uintptr_t>(thread)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    DWORD WINAPI detour_ResumeThread(HANDLE thread)
    {
        if (mrtw::hook_guard)
        {
            return real_ResumeThread(thread);
        }
        mrtw::HookGuard guard;
        DWORD result = real_ResumeThread(thread);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Process","action":"ResumeThread","pid":)" << mrtw::current_pid()
             << R"(,"thread_handle":)" << reinterpret_cast<uintptr_t>(thread)
             << R"(,"result":)" << result
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_process_hooks()
    {
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateProcessW", reinterpret_cast<LPVOID>(&detour_CreateProcessW), reinterpret_cast<LPVOID*>(&real_CreateProcessW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateProcessA", reinterpret_cast<LPVOID>(&detour_CreateProcessA), reinterpret_cast<LPVOID*>(&real_CreateProcessA)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "OpenProcess", reinterpret_cast<LPVOID>(&detour_OpenProcess), reinterpret_cast<LPVOID*>(&real_OpenProcess)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "VirtualAllocEx", reinterpret_cast<LPVOID>(&detour_VirtualAllocEx), reinterpret_cast<LPVOID*>(&real_VirtualAllocEx)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "VirtualProtectEx", reinterpret_cast<LPVOID>(&detour_VirtualProtectEx), reinterpret_cast<LPVOID*>(&real_VirtualProtectEx)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "WriteProcessMemory", reinterpret_cast<LPVOID>(&detour_WriteProcessMemory), reinterpret_cast<LPVOID*>(&real_WriteProcessMemory)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateRemoteThread", reinterpret_cast<LPVOID>(&detour_CreateRemoteThread), reinterpret_cast<LPVOID*>(&real_CreateRemoteThread)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "QueueUserAPC", reinterpret_cast<LPVOID>(&detour_QueueUserAPC), reinterpret_cast<LPVOID*>(&real_QueueUserAPC)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "SetThreadContext", reinterpret_cast<LPVOID>(&detour_SetThreadContext), reinterpret_cast<LPVOID*>(&real_SetThreadContext)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "ResumeThread", reinterpret_cast<LPVOID>(&detour_ResumeThread), reinterpret_cast<LPVOID*>(&real_ResumeThread)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"process_hooks_installed"})" : R"({"source":"hook","event":"process_hooks_failed"})");
        return ok;
    }
}
