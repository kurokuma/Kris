#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using SetUnhandledExceptionFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
    using AddVectoredExceptionHandlerFn = PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    using AddVectoredContinueHandlerFn = PVOID(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
    using OutputDebugStringWFn = VOID(WINAPI*)(LPCWSTR);
    using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);

    SetUnhandledExceptionFilterFn real_SetUnhandledExceptionFilter = nullptr;
    AddVectoredExceptionHandlerFn real_AddVectoredExceptionHandler = nullptr;
    AddVectoredContinueHandlerFn real_AddVectoredContinueHandler = nullptr;
    OutputDebugStringWFn real_OutputDebugStringW = nullptr;
    GetThreadContextFn real_GetThreadContext = nullptr;

    LPTOP_LEVEL_EXCEPTION_FILTER WINAPI detour_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER filter)
    {
        if (mrtw::hook_guard) return real_SetUnhandledExceptionFilter(filter);
        mrtw::HookGuard guard;
        auto result = real_SetUnhandledExceptionFilter(filter);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"SetUnhandledExceptionFilter","pid":)" << mrtw::current_pid()
             << R"(,"filter":)" << reinterpret_cast<uintptr_t>(filter)
             << R"(,"previous":)" << reinterpret_cast<uintptr_t>(result) << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    PVOID WINAPI detour_AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
    {
        if (mrtw::hook_guard) return real_AddVectoredExceptionHandler(first, handler);
        mrtw::HookGuard guard;
        PVOID result = real_AddVectoredExceptionHandler(first, handler);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"AddVectoredExceptionHandler","pid":)" << mrtw::current_pid()
             << R"(,"first":)" << first
             << R"(,"handler":)" << reinterpret_cast<uintptr_t>(handler)
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result) << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    PVOID WINAPI detour_AddVectoredContinueHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
    {
        if (mrtw::hook_guard) return real_AddVectoredContinueHandler(first, handler);
        mrtw::HookGuard guard;
        PVOID result = real_AddVectoredContinueHandler(first, handler);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"AddVectoredContinueHandler","pid":)" << mrtw::current_pid()
             << R"(,"first":)" << first
             << R"(,"handler":)" << reinterpret_cast<uintptr_t>(handler)
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result) << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    VOID WINAPI detour_OutputDebugStringW(LPCWSTR output)
    {
        if (mrtw::hook_guard)
        {
            real_OutputDebugStringW(output);
            return;
        }

        std::string text = mrtw::narrow(output);
        mrtw::HookGuard guard;
        real_OutputDebugStringW(output);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"OutputDebugStringW","pid":)" << mrtw::current_pid()
             << R"(,"message":)" << mrtw::q(text.substr(0, 256)) << "}";
        mrtw::emit_event(json.str());
    }

    BOOL WINAPI detour_GetThreadContext(HANDLE thread, LPCONTEXT context)
    {
        if (mrtw::hook_guard) return real_GetThreadContext(thread, context);
        mrtw::HookGuard guard;
        BOOL result = real_GetThreadContext(thread, context);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"GetThreadContext","pid":)" << mrtw::current_pid()
             << R"(,"thread":)" << reinterpret_cast<uintptr_t>(thread)
             << R"(,"context_flags":)" << (context == nullptr ? 0 : context->ContextFlags)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_evasion_extra_hooks()
    {
        bool ok = true;
        ok &= MH_CreateHookApi(L"kernel32.dll", "SetUnhandledExceptionFilter", reinterpret_cast<LPVOID>(&detour_SetUnhandledExceptionFilter), reinterpret_cast<LPVOID*>(&real_SetUnhandledExceptionFilter)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "AddVectoredExceptionHandler", reinterpret_cast<LPVOID>(&detour_AddVectoredExceptionHandler), reinterpret_cast<LPVOID*>(&real_AddVectoredExceptionHandler)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "AddVectoredContinueHandler", reinterpret_cast<LPVOID>(&detour_AddVectoredContinueHandler), reinterpret_cast<LPVOID*>(&real_AddVectoredContinueHandler)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "OutputDebugStringW", reinterpret_cast<LPVOID>(&detour_OutputDebugStringW), reinterpret_cast<LPVOID*>(&real_OutputDebugStringW)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "GetThreadContext", reinterpret_cast<LPVOID>(&detour_GetThreadContext), reinterpret_cast<LPVOID*>(&real_GetThreadContext)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"evasion_extra_hooks_installed"})" : R"({"source":"hook","event":"evasion_extra_hooks_failed"})");
        return ok;
    }
}
