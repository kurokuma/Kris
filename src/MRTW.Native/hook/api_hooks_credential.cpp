#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>
#include <dbghelp.h>

#include <sstream>

namespace
{
    using CryptUnprotectDataFn = BOOL(WINAPI*)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
    using CredReadWFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, PCREDENTIALW*);
    using MiniDumpWriteDumpFn = BOOL(WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

    CryptUnprotectDataFn real_CryptUnprotectData = nullptr;
    CredReadWFn real_CredReadW = nullptr;
    MiniDumpWriteDumpFn real_MiniDumpWriteDump = nullptr;

    BOOL WINAPI detour_CryptUnprotectData(DATA_BLOB* data_in, LPWSTR* description, DATA_BLOB* optional_entropy, PVOID reserved, CRYPTPROTECT_PROMPTSTRUCT* prompt, DWORD flags, DATA_BLOB* data_out)
    {
        if (mrtw::hook_guard)
        {
            return real_CryptUnprotectData(data_in, description, optional_entropy, reserved, prompt, flags, data_out);
        }

        mrtw::HookGuard guard;
        DWORD input_size = data_in != nullptr ? data_in->cbData : 0;
        BOOL result = real_CryptUnprotectData(data_in, description, optional_entropy, reserved, prompt, flags, data_out);
        DWORD output_size = data_out != nullptr ? data_out->cbData : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Credential","action":"CryptUnprotectData","pid":)" << mrtw::current_pid()
             << R"(,"input_size":)" << input_size
             << R"(,"output_size":)" << output_size
             << R"(,"flags":)" << flags
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CredReadW(LPCWSTR target_name, DWORD type, DWORD flags, PCREDENTIALW* credential)
    {
        if (mrtw::hook_guard)
        {
            return real_CredReadW(target_name, type, flags, credential);
        }

        mrtw::HookGuard guard;
        BOOL result = real_CredReadW(target_name, type, flags, credential);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Credential","action":"CredReadW","pid":)" << mrtw::current_pid()
             << R"(,"target_name":)" << mrtw::q(mrtw::narrow(target_name))
             << R"(,"credential_type":)" << type
             << R"(,"flags":)" << flags
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_MiniDumpWriteDump(HANDLE process, DWORD process_id, HANDLE file, MINIDUMP_TYPE dump_type, PMINIDUMP_EXCEPTION_INFORMATION exception_param, PMINIDUMP_USER_STREAM_INFORMATION user_stream_param, PMINIDUMP_CALLBACK_INFORMATION callback_param)
    {
        if (mrtw::hook_guard)
        {
            return real_MiniDumpWriteDump(process, process_id, file, dump_type, exception_param, user_stream_param, callback_param);
        }

        mrtw::HookGuard guard;
        BOOL result = real_MiniDumpWriteDump(process, process_id, file, dump_type, exception_param, user_stream_param, callback_param);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Credential","action":"MiniDumpWriteDump","pid":)" << mrtw::current_pid()
             << R"(,"target_pid":)" << process_id
             << R"(,"dump_type":)" << static_cast<DWORD>(dump_type)
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_credential_hooks()
    {
        LoadLibraryW(L"crypt32.dll");
        LoadLibraryW(L"advapi32.dll");
        LoadLibraryW(L"dbghelp.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"crypt32.dll", "CryptUnprotectData", reinterpret_cast<LPVOID>(&detour_CryptUnprotectData), reinterpret_cast<LPVOID*>(&real_CryptUnprotectData)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "CredReadW", reinterpret_cast<LPVOID>(&detour_CredReadW), reinterpret_cast<LPVOID*>(&real_CredReadW)) == MH_OK;
        ok &= MH_CreateHookApi(L"dbghelp.dll", "MiniDumpWriteDump", reinterpret_cast<LPVOID>(&detour_MiniDumpWriteDump), reinterpret_cast<LPVOID*>(&real_MiniDumpWriteDump)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"credential_hooks_installed"})" : R"({"source":"hook","event":"credential_hooks_failed"})");
        return ok;
    }
}
