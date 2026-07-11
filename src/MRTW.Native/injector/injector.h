#pragma once

#include <string>

namespace mrtw
{
    struct InjectionRequest
    {
        std::wstring target_path;
        std::wstring command_line;
        std::wstring working_directory;
        std::wstring hook_dll_path;
        std::wstring pipe_name;
        bool start_suspended = true;
        unsigned long hook_init_wait_ms = 8000;
    };

    struct InjectionResult
    {
        int error = 0;
        unsigned long process_id = 0;
    };

    InjectionResult launch_with_hook(const InjectionRequest& request);
}
