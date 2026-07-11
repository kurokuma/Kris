#pragma once

#include <string>

namespace mrtw
{
    bool initialize_hooks(const std::wstring& pipe_name);
    void shutdown_hooks();
    bool emit_event(const std::string& json);
    std::wstring hook_module_path();
}
