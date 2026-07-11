#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <objbase.h>
#include <windows.h>

#include <sstream>

namespace
{
    using CoCreateInstanceFn = HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    using CoCreateInstanceExFn = HRESULT(WINAPI*)(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
    using CoGetClassObjectFn = HRESULT(WINAPI*)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);
    using CLSIDFromProgIDFn = HRESULT(WINAPI*)(LPCOLESTR, LPCLSID);
    using CLSIDFromStringFn = HRESULT(WINAPI*)(LPCOLESTR, LPCLSID);

    CoCreateInstanceFn real_CoCreateInstance = nullptr;
    CoCreateInstanceExFn real_CoCreateInstanceEx = nullptr;
    CoGetClassObjectFn real_CoGetClassObject = nullptr;
    CLSIDFromProgIDFn real_CLSIDFromProgID = nullptr;
    CLSIDFromStringFn real_CLSIDFromString = nullptr;

    std::string guid_to_string(REFGUID guid)
    {
        wchar_t buffer[64] = {};
        StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer)));
        return mrtw::narrow(buffer);
    }

    HRESULT WINAPI detour_CoCreateInstance(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID iid, LPVOID* object)
    {
        if (mrtw::hook_guard) return real_CoCreateInstance(clsid, outer, context, iid, object);
        std::string clsid_text = guid_to_string(clsid);
        std::string iid_text = guid_to_string(iid);
        mrtw::HookGuard guard;
        HRESULT hr = real_CoCreateInstance(clsid, outer, context, iid, object);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CoCreateInstance","pid":)" << mrtw::current_pid()
             << R"(,"clsid":)" << mrtw::q(clsid_text)
             << R"(,"iid":)" << mrtw::q(iid_text)
             << R"(,"context":)" << context
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }

    HRESULT WINAPI detour_CoCreateInstanceEx(REFCLSID clsid, IUnknown* outer, DWORD context, COSERVERINFO* server, DWORD count, MULTI_QI* results)
    {
        if (mrtw::hook_guard) return real_CoCreateInstanceEx(clsid, outer, context, server, count, results);
        std::string clsid_text = guid_to_string(clsid);
        std::string server_name = server == nullptr ? std::string{} : mrtw::narrow(server->pwszName);
        mrtw::HookGuard guard;
        HRESULT hr = real_CoCreateInstanceEx(clsid, outer, context, server, count, results);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CoCreateInstanceEx","pid":)" << mrtw::current_pid()
             << R"(,"clsid":)" << mrtw::q(clsid_text)
             << R"(,"server":)" << mrtw::q(server_name)
             << R"(,"context":)" << context
             << R"(,"query_count":)" << count
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }

    HRESULT WINAPI detour_CoGetClassObject(REFCLSID clsid, DWORD context, LPVOID server, REFIID iid, LPVOID* object)
    {
        if (mrtw::hook_guard) return real_CoGetClassObject(clsid, context, server, iid, object);
        std::string clsid_text = guid_to_string(clsid);
        std::string iid_text = guid_to_string(iid);
        mrtw::HookGuard guard;
        HRESULT hr = real_CoGetClassObject(clsid, context, server, iid, object);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CoGetClassObject","pid":)" << mrtw::current_pid()
             << R"(,"clsid":)" << mrtw::q(clsid_text)
             << R"(,"iid":)" << mrtw::q(iid_text)
             << R"(,"context":)" << context
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }

    HRESULT WINAPI detour_CLSIDFromProgID(LPCOLESTR prog_id, LPCLSID clsid)
    {
        if (mrtw::hook_guard) return real_CLSIDFromProgID(prog_id, clsid);
        std::string prog = mrtw::narrow(prog_id);
        mrtw::HookGuard guard;
        HRESULT hr = real_CLSIDFromProgID(prog_id, clsid);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CLSIDFromProgID","pid":)" << mrtw::current_pid()
             << R"(,"prog_id":)" << mrtw::q(prog)
             << R"(,"clsid":)" << mrtw::q((SUCCEEDED(hr) && clsid != nullptr) ? guid_to_string(*clsid) : std::string{})
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }

    HRESULT WINAPI detour_CLSIDFromString(LPCOLESTR value, LPCLSID clsid)
    {
        if (mrtw::hook_guard) return real_CLSIDFromString(value, clsid);
        std::string text = mrtw::narrow(value);
        mrtw::HookGuard guard;
        HRESULT hr = real_CLSIDFromString(value, clsid);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":"CLSIDFromString","pid":)" << mrtw::current_pid()
             << R"(,"clsid_text":)" << mrtw::q(text)
             << R"(,"hr":)" << hr << "}";
        mrtw::emit_event(json.str());
        return hr;
    }
}

namespace mrtw
{
    bool install_com_wmi_hooks()
    {
        LoadLibraryW(L"ole32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"ole32.dll", "CoCreateInstance", reinterpret_cast<LPVOID>(&detour_CoCreateInstance), reinterpret_cast<LPVOID*>(&real_CoCreateInstance)) == MH_OK;
        ok &= MH_CreateHookApi(L"ole32.dll", "CoCreateInstanceEx", reinterpret_cast<LPVOID>(&detour_CoCreateInstanceEx), reinterpret_cast<LPVOID*>(&real_CoCreateInstanceEx)) == MH_OK;
        ok &= MH_CreateHookApi(L"ole32.dll", "CoGetClassObject", reinterpret_cast<LPVOID>(&detour_CoGetClassObject), reinterpret_cast<LPVOID*>(&real_CoGetClassObject)) == MH_OK;
        ok &= MH_CreateHookApi(L"ole32.dll", "CLSIDFromProgID", reinterpret_cast<LPVOID>(&detour_CLSIDFromProgID), reinterpret_cast<LPVOID*>(&real_CLSIDFromProgID)) == MH_OK;
        ok &= MH_CreateHookApi(L"ole32.dll", "CLSIDFromString", reinterpret_cast<LPVOID>(&detour_CLSIDFromString), reinterpret_cast<LPVOID*>(&real_CLSIDFromString)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"com_wmi_hooks_installed"})" : R"({"source":"hook","event":"com_wmi_hooks_failed"})");
        return ok;
    }
}
