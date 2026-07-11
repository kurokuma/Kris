#include "hook.h"
#include "pipe_client.h"

#include <MinHook.h>
#include <windows.h>

#include <memory>
#include <sstream>
#include <string>

namespace
{
    mrtw::PipeClient g_pipe;
    bool g_initialized = false;
    std::wstring g_module_path;

    struct InitContext
    {
        std::wstring pipe_name;
        std::wstring ready_event_name;
    };

    std::wstring get_env_w(const wchar_t* name)
    {
        DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
        if (required == 0)
        {
            return {};
        }

        std::wstring value(required, L'\0');
        DWORD written = GetEnvironmentVariableW(name, value.data(), required);
        if (written == 0)
        {
            return {};
        }

        value.resize(written);
        return value;
    }

    DWORD WINAPI init_thread(LPVOID parameter)
    {
        std::unique_ptr<InitContext> context(reinterpret_cast<InitContext*>(parameter));
        bool initialized = mrtw::initialize_hooks(context != nullptr ? context->pipe_name : L"");
        if (initialized && context != nullptr && !context->ready_event_name.empty())
        {
            HANDLE ready_event = OpenEventW(EVENT_MODIFY_STATE, FALSE, context->ready_event_name.c_str());
            if (ready_event != nullptr)
            {
                SetEvent(ready_event);
                CloseHandle(ready_event);
            }
        }
        return 0;
    }
}

namespace mrtw
{
    bool initialize_hooks(const std::wstring& pipe_name)
    {
        if (g_initialized)
        {
            return true;
        }

        if (!pipe_name.empty())
        {
            g_pipe.connect(pipe_name);
        }

        if (MH_Initialize() != MH_OK)
        {
            g_pipe.write_jsonl(R"({"source":"hook","event":"minhook_initialize_failed"})");
            return false;
        }

        extern bool install_file_hooks();
        extern bool install_registry_hooks();
        extern bool install_process_hooks();
        extern bool install_network_hooks();
        extern bool install_credential_hooks();
        extern bool install_anti_analysis_hooks();
        extern bool install_module_hooks();
        extern bool install_discovery_hooks();
        extern bool install_token_hooks();
        extern bool install_impact_hooks();
        extern bool install_stealer_hooks();
        extern bool install_tamper_hooks();
        extern bool install_ipc_hooks();
        extern bool install_com_wmi_hooks();
        extern bool install_service_system_hooks();
        extern bool install_environment_hooks();
        extern bool install_evasion_extra_hooks();

        int adapters_total = 0;
        int adapters_healthy = 0;
        auto install = [&](const char* name, bool (*installer)())
        {
            ++adapters_total;
            bool installed = installer();
            if (installed)
            {
                ++adapters_healthy;
            }
            std::ostringstream status;
            status << R"({"source":"hook","category":"Api","action":"Hook Adapter Status","adapter":")"
                   << name << R"(","status":")" << (installed ? "healthy" : "failed") << R"("})";
            g_pipe.write_jsonl(status.str());
        };

        install("file", install_file_hooks);
        install("registry", install_registry_hooks);
        install("process", install_process_hooks);
        install("network", install_network_hooks);
        install("credential", install_credential_hooks);
        install("anti_analysis", install_anti_analysis_hooks);
        install("module", install_module_hooks);
        install("discovery", install_discovery_hooks);
        install("token", install_token_hooks);
        install("impact", install_impact_hooks);
        install("stealer", install_stealer_hooks);
        install("tamper", install_tamper_hooks);
        install("ipc", install_ipc_hooks);
        install("com_wmi", install_com_wmi_hooks);
        install("service_system", install_service_system_hooks);
        install("environment", install_environment_hooks);
        install("evasion_extra", install_evasion_extra_hooks);

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            g_pipe.write_jsonl(R"({"source":"hook","event":"enable_hooks_failed"})");
            return false;
        }

        std::ostringstream summary;
        summary << R"({"source":"hook","category":"Api","action":"Hook Install Summary","status":")"
                << (adapters_healthy == adapters_total ? "healthy" : "degraded")
                << R"(","adapters_total":)" << adapters_total
                << R"(,"adapters_healthy":)" << adapters_healthy
                << R"(,"adapters_failed":)" << (adapters_total - adapters_healthy) << "}";
        g_pipe.write_jsonl(summary.str());

        g_initialized = true;
        g_pipe.write_jsonl(R"({"source":"hook","event":"initialized"})");
        return true;
    }

    void shutdown_hooks()
    {
        if (g_initialized)
        {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            g_initialized = false;
        }

        g_pipe.write_jsonl(R"({"source":"hook","event":"shutdown"})");
        g_pipe.close();
    }

    bool emit_event(const std::string& json)
    {
        return g_pipe.write_jsonl(json);
    }

    std::wstring hook_module_path()
    {
        return g_module_path;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        wchar_t path[MAX_PATH] = {};
        if (GetModuleFileNameW(module, path, MAX_PATH) > 0)
        {
            g_module_path = path;
        }
        auto context = new InitContext
        {
            get_env_w(L"MRTW_HOOK_PIPE"),
            get_env_w(L"MRTW_HOOK_READY_EVENT")
        };
        HANDLE thread = CreateThread(nullptr, 0, init_thread, context, 0, nullptr);
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
        else
        {
            delete context;
        }
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        mrtw::shutdown_hooks();
    }

    return TRUE;
}
