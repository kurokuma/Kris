#include "injector.h"

#include <windows.h>

#include <iostream>
#include <string>

namespace
{
    struct Handle
    {
        HANDLE value = nullptr;
        ~Handle()
        {
            if (value != nullptr && value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(value);
            }
        }
    };

    int inject_dll(HANDLE process, const std::wstring& dll_path)
    {
        SIZE_T bytes = (dll_path.size() + 1) * sizeof(wchar_t);
        LPVOID remote_memory = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remote_memory == nullptr)
        {
            return static_cast<int>(GetLastError());
        }

        if (!WriteProcessMemory(process, remote_memory, dll_path.c_str(), bytes, nullptr))
        {
            DWORD error = GetLastError();
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return static_cast<int>(error);
        }

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
        if (load_library == nullptr)
        {
            DWORD error = GetLastError();
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return static_cast<int>(error);
        }

        Handle thread{ CreateRemoteThread(process, nullptr, 0, load_library, remote_memory, 0, nullptr) };
        if (thread.value == nullptr)
        {
            DWORD error = GetLastError();
            VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return static_cast<int>(error);
        }

        WaitForSingleObject(thread.value, 15000);
        DWORD remote_result = 0;
        GetExitCodeThread(thread.value, &remote_result);
        VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
        return remote_result == 0 ? ERROR_DLL_INIT_FAILED : 0;
    }

    std::wstring make_ready_event_name()
    {
        return L"Local\\MRTW_HOOK_READY_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64());
    }
}

namespace mrtw
{
    InjectionResult launch_with_hook(const InjectionRequest& request)
    {
        if (!request.pipe_name.empty())
        {
            SetEnvironmentVariableW(L"MRTW_HOOK_PIPE", request.pipe_name.c_str());
        }

        std::wstring ready_event_name;
        Handle ready_event;
        if (request.start_suspended)
        {
            ready_event_name = make_ready_event_name();
            ready_event.value = CreateEventW(nullptr, TRUE, FALSE, ready_event_name.c_str());
            if (ready_event.value != nullptr)
            {
                SetEnvironmentVariableW(L"MRTW_HOOK_READY_EVENT", ready_event_name.c_str());
            }
        }

        STARTUPINFOW startup{};
        PROCESS_INFORMATION process{};
        startup.cb = sizeof(startup);

        std::wstring command_line = request.command_line.empty()
            ? L"\"" + request.target_path + L"\""
            : request.command_line;

        DWORD flags = request.start_suspended ? CREATE_SUSPENDED : 0;
        BOOL created = CreateProcessW(
            request.target_path.empty() ? nullptr : request.target_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            flags,
            nullptr,
            request.working_directory.empty() ? nullptr : request.working_directory.c_str(),
            &startup,
            &process);

        if (!request.pipe_name.empty())
        {
            SetEnvironmentVariableW(L"MRTW_HOOK_PIPE", nullptr);
        }
        if (!ready_event_name.empty())
        {
            SetEnvironmentVariableW(L"MRTW_HOOK_READY_EVENT", nullptr);
        }

        if (!created)
        {
            return { static_cast<int>(GetLastError()), 0 };
        }

        DWORD process_id = process.dwProcessId;
        std::cout << R"({"level":"info","event":"process_created","pid":)" << process_id << R"(})" << std::endl;
        Handle process_handle{ process.hProcess };
        Handle thread_handle{ process.hThread };

        int inject_result = inject_dll(process.hProcess, request.hook_dll_path);
        if (inject_result == 0 && request.start_suspended && request.hook_init_wait_ms > 0)
        {
            if (ready_event.value != nullptr)
            {
                WaitForSingleObject(ready_event.value, request.hook_init_wait_ms);
            }
            else
            {
                Sleep(request.hook_init_wait_ms);
            }
        }

        if (request.start_suspended)
        {
            ResumeThread(process.hThread);
        }

        return { inject_result, process_id };
    }
}
