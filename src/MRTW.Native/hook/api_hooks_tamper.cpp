#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <amsi.h>
#include <evntprov.h>
#include <windows.h>

#include <sstream>

namespace
{
    using AmsiScanBufferFn = HRESULT(WINAPI*)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*);
    using EtwEventWriteFn = ULONG(WINAPI*)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
    using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

    AmsiScanBufferFn real_AmsiScanBuffer = nullptr;
    EtwEventWriteFn real_EtwEventWrite = nullptr;
    VirtualProtectFn real_VirtualProtect = nullptr;

    HRESULT WINAPI detour_AmsiScanBuffer(HAMSICONTEXT context, PVOID buffer, ULONG length, LPCWSTR content_name, HAMSISESSION session, AMSI_RESULT* result_out)
    {
        if (mrtw::hook_guard) return real_AmsiScanBuffer(context, buffer, length, content_name, session, result_out);
        std::string name = mrtw::narrow(content_name);
        mrtw::HookGuard guard;
        HRESULT hr = real_AmsiScanBuffer(context, buffer, length, content_name, session, result_out);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"AmsiScanBuffer","pid":)" << mrtw::current_pid()
             << R"(,"content_name":)" << mrtw::q(name)
             << R"(,"buffer_len":)" << length
             << R"(,"amsi_result":)" << (result_out == nullptr ? 0 : static_cast<int>(*result_out))
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }

    ULONG WINAPI detour_EtwEventWrite(REGHANDLE reg_handle, PCEVENT_DESCRIPTOR descriptor, ULONG user_data_count, PEVENT_DATA_DESCRIPTOR user_data)
    {
        if (mrtw::hook_guard) return real_EtwEventWrite(reg_handle, descriptor, user_data_count, user_data);
        mrtw::HookGuard guard;
        ULONG status = real_EtwEventWrite(reg_handle, descriptor, user_data_count, user_data);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"EtwEventWrite","pid":)" << mrtw::current_pid()
             << R"(,"event_id":)" << (descriptor == nullptr ? 0 : descriptor->Id)
             << R"(,"user_data_count":)" << user_data_count
             << R"(,"status":)" << status << "}";
        mrtw::emit_event(json.str());
        return status;
    }

    BOOL WINAPI detour_VirtualProtect(LPVOID address, SIZE_T size, DWORD new_protect, PDWORD old_protect)
    {
        if (mrtw::hook_guard) return real_VirtualProtect(address, size, new_protect, old_protect);
        mrtw::HookGuard guard;
        BOOL result = real_VirtualProtect(address, size, new_protect, old_protect);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"VirtualProtect","pid":)" << mrtw::current_pid()
             << R"(,"address":)" << reinterpret_cast<uintptr_t>(address)
             << R"(,"size":)" << static_cast<unsigned long long>(size)
             << R"(,"new_protect":)" << new_protect
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_tamper_hooks()
    {
        LoadLibraryW(L"amsi.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"amsi.dll", "AmsiScanBuffer", reinterpret_cast<LPVOID>(&detour_AmsiScanBuffer), reinterpret_cast<LPVOID*>(&real_AmsiScanBuffer)) == MH_OK;
        ok &= MH_CreateHookApi(L"ntdll.dll", "EtwEventWrite", reinterpret_cast<LPVOID>(&detour_EtwEventWrite), reinterpret_cast<LPVOID*>(&real_EtwEventWrite)) == MH_OK;
        ok &= MH_CreateHookApi(L"kernel32.dll", "VirtualProtect", reinterpret_cast<LPVOID>(&detour_VirtualProtect), reinterpret_cast<LPVOID*>(&real_VirtualProtect)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"tamper_hooks_installed"})" : R"({"source":"hook","event":"tamper_hooks_failed"})");
        return ok;
    }
}
