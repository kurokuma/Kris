#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>

#include <iostream>
#include <string>

namespace
{
    std::wstring temp_probe_root()
    {
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        return std::wstring(temp) + L"MRTW-Probe";
    }

    void file_probe(const std::wstring& root)
    {
        CreateDirectoryW(root.c_str(), nullptr);
        std::wstring path = root + L"\\native-probe.txt";
        std::wstring moved = root + L"\\native-probe-renamed.txt";

        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE)
        {
            const char text[] = "MRTW NativeSafeRuntimeProbe file write\r\n";
            DWORD written = 0;
            WriteFile(file, text, static_cast<DWORD>(sizeof(text) - 1), &written, nullptr);
            CloseHandle(file);
        }

        DeleteFileW(moved.c_str());
        MoveFileExW(path.c_str(), moved.c_str(), MOVEFILE_REPLACE_EXISTING);
        DeleteFileW(moved.c_str());
        std::wcout << L"file probe complete\n";
    }

    void registry_probe()
    {
        HKEY key = nullptr;
        constexpr wchar_t sub_key[] = L"Software\\MRTW\\Probe";
        if (RegCreateKeyExW(HKEY_CURRENT_USER, sub_key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS)
        {
            const wchar_t value[] = L"NativeSafeRuntimeProbe";
            RegSetValueExW(key, L"ProbeValue", 0, REG_SZ, reinterpret_cast<const BYTE*>(value), static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t)));
            RegCloseKey(key);
        }

        RegDeleteKeyW(HKEY_CURRENT_USER, sub_key);
        std::wcout << L"registry probe complete\n";
    }

    void dll_probe()
    {
        HMODULE module = LoadLibraryW(L"kernel32.dll");
        if (module != nullptr)
        {
            FreeLibrary(module);
        }

        std::wcout << L"dll load probe complete\n";
    }

    void com_probe()
    {
        if (SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)))
        {
            CoUninitialize();
        }

        std::wcout << L"com probe complete\n";
    }

    void localhost_probe()
    {
        WSADATA data = {};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        {
            return;
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET)
        {
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(9);
            InetPtonW(AF_INET, L"127.0.0.1", &addr.sin_addr);
            connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
            closesocket(sock);
        }

        WSACleanup();
        std::wcout << L"localhost probe complete\n";
    }

    void child_process_probe()
    {
        wchar_t command[] = L"cmd.exe /d /c echo MRTW NativeSafeRuntimeProbe child process";
        STARTUPINFOW startup = {};
        PROCESS_INFORMATION info = {};
        startup.cb = sizeof(startup);
        if (CreateProcessW(nullptr, command, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info))
        {
            WaitForSingleObject(info.hProcess, 3000);
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        }

        std::wcout << L"child process probe complete\n";
    }
}

int wmain()
{
    std::wcout << L"MRTW NativeSafeRuntimeProbe started\n";
    std::wcout << L"This program only touches temporary MRTW-Probe resources and localhost.\n";
    Sleep(3000);

    std::wstring root = temp_probe_root();
    file_probe(root);
    registry_probe();
    dll_probe();
    com_probe();
    localhost_probe();
    child_process_probe();

    std::wcout << L"MRTW NativeSafeRuntimeProbe completed\n";
    return 0;
}
