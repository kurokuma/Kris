#include "hook.h"
#include "hook_state.h"
#include "json_util.h"

#include <MinHook.h>
#include <windows.h>

#include <sstream>

namespace
{
    using OpenClipboardFn = BOOL(WINAPI*)(HWND);
    using GetClipboardDataFn = HANDLE(WINAPI*)(UINT);
    using SetClipboardDataFn = HANDLE(WINAPI*)(UINT, HANDLE);
    using GetDCFn = HDC(WINAPI*)(HWND);
    using ReleaseDCFn = int(WINAPI*)(HWND, HDC);
    using BitBltFn = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, DWORD);
    using CreateCompatibleBitmapFn = HBITMAP(WINAPI*)(HDC, int, int);
    using GetAsyncKeyStateFn = SHORT(WINAPI*)(int);
    using GetKeyStateFn = SHORT(WINAPI*)(int);
    using SetWindowsHookExWFn = HHOOK(WINAPI*)(int, HOOKPROC, HINSTANCE, DWORD);

    OpenClipboardFn real_OpenClipboard = nullptr;
    GetClipboardDataFn real_GetClipboardData = nullptr;
    SetClipboardDataFn real_SetClipboardData = nullptr;
    GetDCFn real_GetDC = nullptr;
    ReleaseDCFn real_ReleaseDC = nullptr;
    BitBltFn real_BitBlt = nullptr;
    CreateCompatibleBitmapFn real_CreateCompatibleBitmap = nullptr;
    GetAsyncKeyStateFn real_GetAsyncKeyState = nullptr;
    GetKeyStateFn real_GetKeyState = nullptr;
    SetWindowsHookExWFn real_SetWindowsHookExW = nullptr;

    void emit_simple(const char* action, const std::string& extra)
    {
        std::ostringstream json;
        json << R"({"source":"hook","category":"Api","action":")" << action << R"(","pid":)" << mrtw::current_pid() << extra << "}";
        mrtw::emit_event(json.str());
    }

    BOOL WINAPI detour_OpenClipboard(HWND owner)
    {
        if (mrtw::hook_guard) return real_OpenClipboard(owner);
        mrtw::HookGuard guard;
        BOOL result = real_OpenClipboard(owner);
        emit_simple("OpenClipboard", std::string(R"(,"owner":)") + std::to_string(reinterpret_cast<uintptr_t>(owner)) + R"(,"result":)" + (result ? "true" : "false") + R"(,"last_error":)" + std::to_string(GetLastError()));
        return result;
    }

    HANDLE WINAPI detour_GetClipboardData(UINT format)
    {
        if (mrtw::hook_guard) return real_GetClipboardData(format);
        mrtw::HookGuard guard;
        HANDLE result = real_GetClipboardData(format);
        emit_simple("GetClipboardData", std::string(R"(,"clipboard_format":)") + std::to_string(format) + R"(,"result":)" + std::to_string(reinterpret_cast<uintptr_t>(result)) + R"(,"last_error":)" + std::to_string(GetLastError()));
        return result;
    }

    HANDLE WINAPI detour_SetClipboardData(UINT format, HANDLE memory)
    {
        if (mrtw::hook_guard) return real_SetClipboardData(format, memory);
        mrtw::HookGuard guard;
        HANDLE result = real_SetClipboardData(format, memory);
        emit_simple("SetClipboardData", std::string(R"(,"clipboard_format":)") + std::to_string(format) + R"(,"result":)" + std::to_string(reinterpret_cast<uintptr_t>(result)) + R"(,"last_error":)" + std::to_string(GetLastError()));
        return result;
    }

    HDC WINAPI detour_GetDC(HWND window)
    {
        if (mrtw::hook_guard) return real_GetDC(window);
        mrtw::HookGuard guard;
        HDC result = real_GetDC(window);
        emit_simple("GetDC", std::string(R"(,"window":)") + std::to_string(reinterpret_cast<uintptr_t>(window)) + R"(,"result":)" + std::to_string(reinterpret_cast<uintptr_t>(result)));
        return result;
    }

    int WINAPI detour_ReleaseDC(HWND window, HDC dc)
    {
        if (mrtw::hook_guard) return real_ReleaseDC(window, dc);
        mrtw::HookGuard guard;
        int result = real_ReleaseDC(window, dc);
        emit_simple("ReleaseDC", std::string(R"(,"window":)") + std::to_string(reinterpret_cast<uintptr_t>(window)) + R"(,"result":)" + std::to_string(result));
        return result;
    }

    BOOL WINAPI detour_BitBlt(HDC dest, int x, int y, int cx, int cy, HDC src, int x1, int y1, DWORD rop)
    {
        if (mrtw::hook_guard) return real_BitBlt(dest, x, y, cx, cy, src, x1, y1, rop);
        mrtw::HookGuard guard;
        BOOL result = real_BitBlt(dest, x, y, cx, cy, src, x1, y1, rop);
        emit_simple("BitBlt", std::string(R"(,"width":)") + std::to_string(cx) + R"(,"height":)" + std::to_string(cy) + R"(,"rop":)" + std::to_string(rop) + R"(,"result":)" + (result ? "true" : "false"));
        return result;
    }

    HBITMAP WINAPI detour_CreateCompatibleBitmap(HDC dc, int cx, int cy)
    {
        if (mrtw::hook_guard) return real_CreateCompatibleBitmap(dc, cx, cy);
        mrtw::HookGuard guard;
        HBITMAP result = real_CreateCompatibleBitmap(dc, cx, cy);
        emit_simple("CreateCompatibleBitmap", std::string(R"(,"width":)") + std::to_string(cx) + R"(,"height":)" + std::to_string(cy) + R"(,"result":)" + std::to_string(reinterpret_cast<uintptr_t>(result)));
        return result;
    }

    SHORT WINAPI detour_GetAsyncKeyState(int key)
    {
        if (mrtw::hook_guard) return real_GetAsyncKeyState(key);
        mrtw::HookGuard guard;
        SHORT result = real_GetAsyncKeyState(key);
        emit_simple("GetAsyncKeyState", std::string(R"(,"virtual_key":)") + std::to_string(key) + R"(,"result":)" + std::to_string(result));
        return result;
    }

    SHORT WINAPI detour_GetKeyState(int key)
    {
        if (mrtw::hook_guard) return real_GetKeyState(key);
        mrtw::HookGuard guard;
        SHORT result = real_GetKeyState(key);
        emit_simple("GetKeyState", std::string(R"(,"virtual_key":)") + std::to_string(key) + R"(,"result":)" + std::to_string(result));
        return result;
    }

    HHOOK WINAPI detour_SetWindowsHookExW(int id_hook, HOOKPROC proc, HINSTANCE module, DWORD thread_id)
    {
        if (mrtw::hook_guard) return real_SetWindowsHookExW(id_hook, proc, module, thread_id);
        mrtw::HookGuard guard;
        HHOOK result = real_SetWindowsHookExW(id_hook, proc, module, thread_id);
        emit_simple("SetWindowsHookExW", std::string(R"(,"hook_id":)") + std::to_string(id_hook) + R"(,"thread_id":)" + std::to_string(thread_id) + R"(,"result":)" + std::to_string(reinterpret_cast<uintptr_t>(result)) + R"(,"last_error":)" + std::to_string(GetLastError()));
        return result;
    }
}

namespace mrtw
{
    bool install_stealer_hooks()
    {
        LoadLibraryW(L"user32.dll");
        LoadLibraryW(L"gdi32.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"user32.dll", "OpenClipboard", reinterpret_cast<LPVOID>(&detour_OpenClipboard), reinterpret_cast<LPVOID*>(&real_OpenClipboard)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "GetClipboardData", reinterpret_cast<LPVOID>(&detour_GetClipboardData), reinterpret_cast<LPVOID*>(&real_GetClipboardData)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "SetClipboardData", reinterpret_cast<LPVOID>(&detour_SetClipboardData), reinterpret_cast<LPVOID*>(&real_SetClipboardData)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "GetDC", reinterpret_cast<LPVOID>(&detour_GetDC), reinterpret_cast<LPVOID*>(&real_GetDC)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "ReleaseDC", reinterpret_cast<LPVOID>(&detour_ReleaseDC), reinterpret_cast<LPVOID*>(&real_ReleaseDC)) == MH_OK;
        ok &= MH_CreateHookApi(L"gdi32.dll", "BitBlt", reinterpret_cast<LPVOID>(&detour_BitBlt), reinterpret_cast<LPVOID*>(&real_BitBlt)) == MH_OK;
        ok &= MH_CreateHookApi(L"gdi32.dll", "CreateCompatibleBitmap", reinterpret_cast<LPVOID>(&detour_CreateCompatibleBitmap), reinterpret_cast<LPVOID*>(&real_CreateCompatibleBitmap)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "GetAsyncKeyState", reinterpret_cast<LPVOID>(&detour_GetAsyncKeyState), reinterpret_cast<LPVOID*>(&real_GetAsyncKeyState)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "GetKeyState", reinterpret_cast<LPVOID>(&detour_GetKeyState), reinterpret_cast<LPVOID*>(&real_GetKeyState)) == MH_OK;
        ok &= MH_CreateHookApi(L"user32.dll", "SetWindowsHookExW", reinterpret_cast<LPVOID>(&detour_SetWindowsHookExW), reinterpret_cast<LPVOID*>(&real_SetWindowsHookExW)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"stealer_hooks_installed"})" : R"({"source":"hook","event":"stealer_hooks_failed"})");
        return ok;
    }
}
