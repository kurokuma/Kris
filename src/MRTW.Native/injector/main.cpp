#include "injector.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <unordered_map>

namespace
{
    std::unordered_map<std::wstring, std::wstring> parse_args(int argc, wchar_t** argv)
    {
        std::unordered_map<std::wstring, std::wstring> values;
        for (int i = 1; i < argc; ++i)
        {
            std::wstring key = argv[i];
            if (key.rfind(L"--", 0) != 0)
            {
                continue;
            }

            if (i + 1 < argc && std::wstring(argv[i + 1]).rfind(L"--", 0) != 0)
            {
                values[key.substr(2)] = argv[++i];
            }
            else
            {
                values[key.substr(2)] = L"true";
            }
        }

        return values;
    }

    std::wstring get_value(const std::unordered_map<std::wstring, std::wstring>& args, const wchar_t* key)
    {
        auto found = args.find(key);
        return found == args.end() ? L"" : found->second;
    }

    std::string narrow(const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(static_cast<size_t>(required - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), required, nullptr, nullptr);
        return result;
    }
}

int wmain(int argc, wchar_t** argv)
{
    auto args = parse_args(argc, argv);
    mrtw::InjectionRequest request;
    request.target_path = get_value(args, L"target");
    request.command_line = get_value(args, L"cmd");
    request.working_directory = get_value(args, L"working-dir");
    request.hook_dll_path = get_value(args, L"hook");
    request.pipe_name = get_value(args, L"pipe");
    request.start_suspended = get_value(args, L"suspended") != L"off";
    std::wstring wait = get_value(args, L"hook-init-wait-ms");
    if (!wait.empty())
    {
        request.hook_init_wait_ms = std::wcstoul(wait.c_str(), nullptr, 10);
    }

    if (request.hook_dll_path.empty() || (request.target_path.empty() && request.command_line.empty()))
    {
        std::cout << R"({"level":"error","event":"invalid_arguments","message":"--hook and --target or --cmd are required"})" << std::endl;
        return 1;
    }

    mrtw::InjectionResult result = mrtw::launch_with_hook(request);
    if (result.error == 0)
    {
        std::cout << R"({"level":"info","event":"injection_completed","pid":)" << result.process_id << R"(})" << std::endl;
        return 0;
    }

    std::cout << R"({"level":"error","event":"injection_failed","win32_error":)" << result.error
              << R"(,"pid":)" << result.process_id
              << R"(,"target":")" << narrow(request.target_path) << R"("})" << std::endl;
    return result.error;
}
