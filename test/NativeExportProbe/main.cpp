#include <windows.h>

extern "C" __declspec(dllexport) HRESULT __stdcall DllRegisterServer()
{
    return S_OK;
}

extern "C" __declspec(dllexport) int __stdcall Start()
{
    return 0;
}

extern "C" __declspec(dllexport) int __stdcall Run()
{
    return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}
