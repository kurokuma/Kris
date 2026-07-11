#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    using DeleteFileWFn = BOOL(WINAPI*)(LPCWSTR);
    using MoveFileExWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
    using CopyFileWFn = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, BOOL);
    using CreateDirectoryWFn = BOOL(WINAPI*)(LPCWSTR, LPSECURITY_ATTRIBUTES);
    using SetFileAttributesWFn = BOOL(WINAPI*)(LPCWSTR, DWORD);
    using SetFileInformationByHandleFn = BOOL(WINAPI*)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);

    CreateFileWFn real_CreateFileW = nullptr;
    WriteFileFn real_WriteFile = nullptr;
    DeleteFileWFn real_DeleteFileW = nullptr;
    MoveFileExWFn real_MoveFileExW = nullptr;
    CopyFileWFn real_CopyFileW = nullptr;
    CreateDirectoryWFn real_CreateDirectoryW = nullptr;
    SetFileAttributesWFn real_SetFileAttributesW = nullptr;
    SetFileInformationByHandleFn real_SetFileInformationByHandle = nullptr;
    CreateFileWFn real_KernelBase_CreateFileW = nullptr;
    WriteFileFn real_KernelBase_WriteFile = nullptr;
    DeleteFileWFn real_KernelBase_DeleteFileW = nullptr;
    MoveFileExWFn real_KernelBase_MoveFileExW = nullptr;
    CopyFileWFn real_KernelBase_CopyFileW = nullptr;
    CreateDirectoryWFn real_KernelBase_CreateDirectoryW = nullptr;
    SetFileAttributesWFn real_KernelBase_SetFileAttributesW = nullptr;
    SetFileInformationByHandleFn real_KernelBase_SetFileInformationByHandle = nullptr;

    const char* disposition_name(DWORD disposition)
    {
        switch (disposition)
        {
        case CREATE_NEW: return "CREATE_NEW";
        case CREATE_ALWAYS: return "CREATE_ALWAYS";
        case OPEN_EXISTING: return "OPEN_EXISTING";
        case OPEN_ALWAYS: return "OPEN_ALWAYS";
        case TRUNCATE_EXISTING: return "TRUNCATE_EXISTING";
        default: return "UNKNOWN";
        }
    }

    void emit_create_file(LPCWSTR file_name, DWORD access, DWORD share, DWORD disposition, DWORD flags, HANDLE result)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"CreateFileW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"desired_access":)" << access
             << R"(,"share_mode":)" << share
             << R"(,"disposition":)" << mrtw::q(disposition_name(disposition))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
    }

    void emit_write_file(HANDLE file, DWORD bytes_to_write, LPDWORD bytes_written, BOOL result)
    {
        DWORD actual = bytes_written != nullptr ? *bytes_written : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"WriteFile","pid":)" << mrtw::current_pid()
             << R"(,"handle":)" << reinterpret_cast<uintptr_t>(file)
             << R"(,"requested_bytes":)" << bytes_to_write
             << R"(,"written_bytes":)" << actual
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
    }

    HANDLE WINAPI detour_CreateFileW(LPCWSTR file_name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD disposition, DWORD flags, HANDLE template_file)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateFileW(file_name, access, share, security, disposition, flags, template_file);
        }

        mrtw::HookGuard guard;
        HANDLE result = real_CreateFileW(file_name, access, share, security, disposition, flags, template_file);
        emit_create_file(file_name, access, share, disposition, flags, result);
        return result;
    }

    HANDLE WINAPI detour_KernelBase_CreateFileW(LPCWSTR file_name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security, DWORD disposition, DWORD flags, HANDLE template_file)
    {
        if (mrtw::hook_guard)
        {
            return real_KernelBase_CreateFileW(file_name, access, share, security, disposition, flags, template_file);
        }

        mrtw::HookGuard guard;
        HANDLE result = real_KernelBase_CreateFileW(file_name, access, share, security, disposition, flags, template_file);
        emit_create_file(file_name, access, share, disposition, flags, result);
        return result;
    }

    BOOL WINAPI detour_WriteFile(HANDLE file, LPCVOID buffer, DWORD bytes_to_write, LPDWORD bytes_written, LPOVERLAPPED overlapped)
    {
        if (mrtw::hook_guard)
        {
            return real_WriteFile(file, buffer, bytes_to_write, bytes_written, overlapped);
        }

        mrtw::HookGuard guard;
        BOOL result = real_WriteFile(file, buffer, bytes_to_write, bytes_written, overlapped);
        emit_write_file(file, bytes_to_write, bytes_written, result);
        return result;
    }

    BOOL WINAPI detour_KernelBase_WriteFile(HANDLE file, LPCVOID buffer, DWORD bytes_to_write, LPDWORD bytes_written, LPOVERLAPPED overlapped)
    {
        if (mrtw::hook_guard)
        {
            return real_KernelBase_WriteFile(file, buffer, bytes_to_write, bytes_written, overlapped);
        }

        mrtw::HookGuard guard;
        BOOL result = real_KernelBase_WriteFile(file, buffer, bytes_to_write, bytes_written, overlapped);
        emit_write_file(file, bytes_to_write, bytes_written, result);
        return result;
    }

    BOOL WINAPI detour_DeleteFileW(LPCWSTR file_name)
    {
        if (mrtw::hook_guard)
        {
            return real_DeleteFileW(file_name);
        }
        mrtw::HookGuard guard;
        BOOL result = real_DeleteFileW(file_name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"DeleteFileW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_KernelBase_DeleteFileW(LPCWSTR file_name)
    {
        if (mrtw::hook_guard)
        {
            return real_KernelBase_DeleteFileW(file_name);
        }
        mrtw::HookGuard guard;
        BOOL result = real_KernelBase_DeleteFileW(file_name);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"DeleteFileW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_MoveFileExW(LPCWSTR existing_file_name, LPCWSTR new_file_name, DWORD flags)
    {
        if (mrtw::hook_guard)
        {
            return real_MoveFileExW(existing_file_name, new_file_name, flags);
        }
        mrtw::HookGuard guard;
        BOOL result = real_MoveFileExW(existing_file_name, new_file_name, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"MoveFileExW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(existing_file_name))
             << R"(,"new_path":)" << mrtw::q(mrtw::narrow(new_file_name))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_KernelBase_MoveFileExW(LPCWSTR existing_file_name, LPCWSTR new_file_name, DWORD flags)
    {
        if (mrtw::hook_guard)
        {
            return real_KernelBase_MoveFileExW(existing_file_name, new_file_name, flags);
        }
        mrtw::HookGuard guard;
        BOOL result = real_KernelBase_MoveFileExW(existing_file_name, new_file_name, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"MoveFileExW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(existing_file_name))
             << R"(,"new_path":)" << mrtw::q(mrtw::narrow(new_file_name))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CopyFileW(LPCWSTR existing_file_name, LPCWSTR new_file_name, BOOL fail_if_exists)
    {
        if (mrtw::hook_guard)
        {
            return real_CopyFileW(existing_file_name, new_file_name, fail_if_exists);
        }
        mrtw::HookGuard guard;
        BOOL result = real_CopyFileW(existing_file_name, new_file_name, fail_if_exists);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"CopyFileW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(existing_file_name))
             << R"(,"new_path":)" << mrtw::q(mrtw::narrow(new_file_name))
             << R"(,"fail_if_exists":)" << (fail_if_exists ? "true" : "false")
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CreateDirectoryW(LPCWSTR path_name, LPSECURITY_ATTRIBUTES security)
    {
        if (mrtw::hook_guard)
        {
            return real_CreateDirectoryW(path_name, security);
        }
        mrtw::HookGuard guard;
        BOOL result = real_CreateDirectoryW(path_name, security);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"CreateDirectoryW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(path_name))
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_SetFileAttributesW(LPCWSTR file_name, DWORD attributes)
    {
        if (mrtw::hook_guard)
        {
            return real_SetFileAttributesW(file_name, attributes);
        }
        mrtw::HookGuard guard;
        BOOL result = real_SetFileAttributesW(file_name, attributes);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"SetFileAttributesW","pid":)" << mrtw::current_pid()
             << R"(,"path":)" << mrtw::q(mrtw::narrow(file_name))
             << R"(,"attributes":)" << attributes
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_SetFileInformationByHandle(HANDLE file, FILE_INFO_BY_HANDLE_CLASS info_class, LPVOID info, DWORD buffer_size)
    {
        if (mrtw::hook_guard)
        {
            return real_SetFileInformationByHandle(file, info_class, info, buffer_size);
        }
        mrtw::HookGuard guard;
        BOOL result = real_SetFileInformationByHandle(file, info_class, info, buffer_size);
        std::ostringstream json;
        json << R"({"source":"hook","category":"File","action":"SetFileInformationByHandle","pid":)" << mrtw::current_pid()
             << R"(,"handle":)" << reinterpret_cast<uintptr_t>(file)
             << R"(,"info_class":)" << static_cast<int>(info_class)
             << R"(,"buffer_size":)" << buffer_size
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_file_hooks()
    {
        LoadLibraryW(L"KernelBase.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateFileW", reinterpret_cast<LPVOID>(&detour_CreateFileW), reinterpret_cast<LPVOID*>(&real_CreateFileW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "WriteFile", reinterpret_cast<LPVOID>(&detour_WriteFile), reinterpret_cast<LPVOID*>(&real_WriteFile)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "DeleteFileW", reinterpret_cast<LPVOID>(&detour_DeleteFileW), reinterpret_cast<LPVOID*>(&real_DeleteFileW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "MoveFileExW", reinterpret_cast<LPVOID>(&detour_MoveFileExW), reinterpret_cast<LPVOID*>(&real_MoveFileExW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CopyFileW", reinterpret_cast<LPVOID>(&detour_CopyFileW), reinterpret_cast<LPVOID*>(&real_CopyFileW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "CreateDirectoryW", reinterpret_cast<LPVOID>(&detour_CreateDirectoryW), reinterpret_cast<LPVOID*>(&real_CreateDirectoryW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "SetFileAttributesW", reinterpret_cast<LPVOID>(&detour_SetFileAttributesW), reinterpret_cast<LPVOID*>(&real_SetFileAttributesW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "SetFileInformationByHandle", reinterpret_cast<LPVOID>(&detour_SetFileInformationByHandle), reinterpret_cast<LPVOID*>(&real_SetFileInformationByHandle)) == MH_OK;
        MH_CreateHookApi(L"KernelBase.dll", "CreateFileW", reinterpret_cast<LPVOID>(&detour_KernelBase_CreateFileW), reinterpret_cast<LPVOID*>(&real_KernelBase_CreateFileW));
        MH_CreateHookApi(L"KernelBase.dll", "WriteFile", reinterpret_cast<LPVOID>(&detour_KernelBase_WriteFile), reinterpret_cast<LPVOID*>(&real_KernelBase_WriteFile));
        MH_CreateHookApi(L"KernelBase.dll", "DeleteFileW", reinterpret_cast<LPVOID>(&detour_KernelBase_DeleteFileW), reinterpret_cast<LPVOID*>(&real_KernelBase_DeleteFileW));
        MH_CreateHookApi(L"KernelBase.dll", "MoveFileExW", reinterpret_cast<LPVOID>(&detour_KernelBase_MoveFileExW), reinterpret_cast<LPVOID*>(&real_KernelBase_MoveFileExW));
        emit_event(ok ? R"({"source":"hook","event":"file_hooks_installed"})" : R"({"source":"hook","event":"file_hooks_failed"})");
        return ok;
    }
}
