#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <sstream>

namespace
{
    using CryptEncryptFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
    using CryptGenRandomFn = BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*);
    using BCryptEncryptFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    using BCryptGenerateSymmetricKeyFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);

    CryptEncryptFn real_CryptEncrypt = nullptr;
    CryptGenRandomFn real_CryptGenRandom = nullptr;
    BCryptEncryptFn real_BCryptEncrypt = nullptr;
    BCryptGenerateSymmetricKeyFn real_BCryptGenerateSymmetricKey = nullptr;

    BOOL WINAPI detour_CryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL final, DWORD flags, BYTE* data, DWORD* data_len, DWORD buffer_len)
    {
        if (mrtw::hook_guard) return real_CryptEncrypt(key, hash, final, flags, data, data_len, buffer_len);
        mrtw::HookGuard guard;
        BOOL result = real_CryptEncrypt(key, hash, final, flags, data, data_len, buffer_len);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CryptEncrypt","pid":)" << mrtw::current_pid()
             << R"(,"data_len":)" << (data_len == nullptr ? 0 : *data_len)
             << R"(,"buffer_len":)" << buffer_len
             << R"(,"final":)" << (final ? "true" : "false")
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_CryptGenRandom(HCRYPTPROV provider, DWORD length, BYTE* buffer)
    {
        if (mrtw::hook_guard) return real_CryptGenRandom(provider, length, buffer);
        mrtw::HookGuard guard;
        BOOL result = real_CryptGenRandom(provider, length, buffer);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CryptGenRandom","pid":)" << mrtw::current_pid()
             << R"(,"length":)" << length
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError() << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    NTSTATUS WINAPI detour_BCryptEncrypt(BCRYPT_KEY_HANDLE key, PUCHAR input, ULONG input_size, VOID* padding_info, PUCHAR iv, ULONG iv_size, PUCHAR output, ULONG output_size, ULONG* result_size, ULONG flags)
    {
        if (mrtw::hook_guard) return real_BCryptEncrypt(key, input, input_size, padding_info, iv, iv_size, output, output_size, result_size, flags);
        mrtw::HookGuard guard;
        NTSTATUS status = real_BCryptEncrypt(key, input, input_size, padding_info, iv, iv_size, output, output_size, result_size, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"BCryptEncrypt","pid":)" << mrtw::current_pid()
             << R"(,"input_size":)" << input_size
             << R"(,"output_size":)" << output_size
             << R"(,"result_size":)" << (result_size == nullptr ? 0 : *result_size)
             << R"(,"flags":)" << flags
             << R"(,"status":)" << status << "}";
        mrtw::emit_event(json.str());
        return status;
    }

    NTSTATUS WINAPI detour_BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE* key, PUCHAR key_object, ULONG key_object_size, PUCHAR secret, ULONG secret_size, ULONG flags)
    {
        if (mrtw::hook_guard) return real_BCryptGenerateSymmetricKey(algorithm, key, key_object, key_object_size, secret, secret_size, flags);
        mrtw::HookGuard guard;
        NTSTATUS status = real_BCryptGenerateSymmetricKey(algorithm, key, key_object, key_object_size, secret, secret_size, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"BCryptGenerateSymmetricKey","pid":)" << mrtw::current_pid()
             << R"(,"secret_size":)" << secret_size
             << R"(,"flags":)" << flags
             << R"(,"status":)" << status << "}";
        mrtw::emit_event(json.str());
        return status;
    }
}

namespace mrtw
{
    bool install_impact_hooks()
    {
        LoadLibraryW(L"advapi32.dll");
        LoadLibraryW(L"bcrypt.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"advapi32.dll", "CryptEncrypt", reinterpret_cast<LPVOID>(&detour_CryptEncrypt), reinterpret_cast<LPVOID*>(&real_CryptEncrypt)) == MH_OK;
        ok &= MH_CreateHookApi(L"advapi32.dll", "CryptGenRandom", reinterpret_cast<LPVOID>(&detour_CryptGenRandom), reinterpret_cast<LPVOID*>(&real_CryptGenRandom)) == MH_OK;
        ok &= MH_CreateHookApi(L"bcrypt.dll", "BCryptEncrypt", reinterpret_cast<LPVOID>(&detour_BCryptEncrypt), reinterpret_cast<LPVOID*>(&real_BCryptEncrypt)) == MH_OK;
        ok &= MH_CreateHookApi(L"bcrypt.dll", "BCryptGenerateSymmetricKey", reinterpret_cast<LPVOID>(&detour_BCryptGenerateSymmetricKey), reinterpret_cast<LPVOID*>(&real_BCryptGenerateSymmetricKey)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"impact_hooks_installed"})" : R"({"source":"hook","event":"impact_hooks_failed"})");
        return ok;
    }
}
