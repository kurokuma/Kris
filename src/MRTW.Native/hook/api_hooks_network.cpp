#include "hook.h"
#include "hook_state.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#include "json_util.h"

#include <MinHook.h>
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>

#include <sstream>

namespace
{
    using WinHttpConnectFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    using WinHttpOpenRequestFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    using WinHttpSendRequestFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    using HttpOpenRequestWFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
    using HttpSendRequestWFn = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
    using ConnectFn = int(WSAAPI*)(SOCKET, const sockaddr*, int);
    using WSAConnectFn = int(WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
    using SendFn = int(WSAAPI*)(SOCKET, const char*, int, int);
    using WSASendFn = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using DnsQueryWFn = DNS_STATUS(WINAPI*)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
    using DnsQueryAFn = DNS_STATUS(WINAPI*)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORDA*, PVOID*);
    using GetAddrInfoWFn = INT(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
    using GetAddrInfoAFn = INT(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);

    WinHttpConnectFn real_WinHttpConnect = nullptr;
    WinHttpOpenRequestFn real_WinHttpOpenRequest = nullptr;
    WinHttpSendRequestFn real_WinHttpSendRequest = nullptr;
    HttpOpenRequestWFn real_HttpOpenRequestW = nullptr;
    HttpSendRequestWFn real_HttpSendRequestW = nullptr;
    ConnectFn real_connect = nullptr;
    WSAConnectFn real_WSAConnect = nullptr;
    SendFn real_send = nullptr;
    WSASendFn real_WSASend = nullptr;
    DnsQueryWFn real_DnsQuery_W = nullptr;
    DnsQueryAFn real_DnsQuery_A = nullptr;
    GetAddrInfoWFn real_GetAddrInfoW = nullptr;
    GetAddrInfoAFn real_getaddrinfo = nullptr;

    std::string socket_endpoint(const sockaddr* name)
    {
        if (name == nullptr)
        {
            return {};
        }

        char host[INET6_ADDRSTRLEN] = {};
        unsigned short port = 0;
        if (name->sa_family == AF_INET)
        {
            const auto* addr = reinterpret_cast<const sockaddr_in*>(name);
            InetNtopA(AF_INET, const_cast<IN_ADDR*>(&addr->sin_addr), host, static_cast<DWORD>(sizeof(host)));
            port = ntohs(addr->sin_port);
        }
        else if (name->sa_family == AF_INET6)
        {
            const auto* addr = reinterpret_cast<const sockaddr_in6*>(name);
            InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&addr->sin6_addr), host, static_cast<DWORD>(sizeof(host)));
            port = ntohs(addr->sin6_port);
        }
        else
        {
            return "af-" + std::to_string(name->sa_family);
        }

        std::ostringstream endpoint;
        endpoint << host << ":" << port;
        return endpoint.str();
    }

    HINTERNET WINAPI detour_WinHttpConnect(HINTERNET session, LPCWSTR server_name, INTERNET_PORT port, DWORD reserved)
    {
        if (mrtw::hook_guard)
        {
            return real_WinHttpConnect(session, server_name, port, reserved);
        }

        mrtw::HookGuard guard;
        HINTERNET result = real_WinHttpConnect(session, server_name, port, reserved);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WinHttpConnect","pid":)" << mrtw::current_pid()
             << R"(,"server":)" << mrtw::q(mrtw::narrow(server_name))
             << R"(,"port":)" << port
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HINTERNET WINAPI detour_WinHttpOpenRequest(HINTERNET connect, LPCWSTR verb, LPCWSTR object_name, LPCWSTR version, LPCWSTR referrer, LPCWSTR* accept_types, DWORD flags)
    {
        if (mrtw::hook_guard)
        {
            return real_WinHttpOpenRequest(connect, verb, object_name, version, referrer, accept_types, flags);
        }

        mrtw::HookGuard guard;
        HINTERNET result = real_WinHttpOpenRequest(connect, verb, object_name, version, referrer, accept_types, flags);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WinHttpOpenRequest","pid":)" << mrtw::current_pid()
             << R"(,"verb":)" << mrtw::q(mrtw::narrow(verb))
             << R"(,"object":)" << mrtw::q(mrtw::narrow(object_name))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_WinHttpSendRequest(HINTERNET request, LPCWSTR headers, DWORD headers_length, LPVOID optional, DWORD optional_length, DWORD total_length, DWORD_PTR context)
    {
        if (mrtw::hook_guard)
        {
            return real_WinHttpSendRequest(request, headers, headers_length, optional, optional_length, total_length, context);
        }

        mrtw::HookGuard guard;
        BOOL result = real_WinHttpSendRequest(request, headers, headers_length, optional, optional_length, total_length, context);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WinHttpSendRequest","pid":)" << mrtw::current_pid()
             << R"(,"headers_length":)" << headers_length
             << R"(,"optional_length":)" << optional_length
             << R"(,"total_length":)" << total_length
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    HINTERNET WINAPI detour_HttpOpenRequestW(HINTERNET connect, LPCWSTR verb, LPCWSTR object_name, LPCWSTR version, LPCWSTR referrer, LPCWSTR* accept_types, DWORD flags, DWORD_PTR context)
    {
        if (mrtw::hook_guard)
        {
            return real_HttpOpenRequestW(connect, verb, object_name, version, referrer, accept_types, flags, context);
        }

        mrtw::HookGuard guard;
        HINTERNET result = real_HttpOpenRequestW(connect, verb, object_name, version, referrer, accept_types, flags, context);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"HttpOpenRequestW","pid":)" << mrtw::current_pid()
             << R"(,"verb":)" << mrtw::q(mrtw::narrow(verb))
             << R"(,"object":)" << mrtw::q(mrtw::narrow(object_name))
             << R"(,"flags":)" << flags
             << R"(,"result":)" << reinterpret_cast<uintptr_t>(result)
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    BOOL WINAPI detour_HttpSendRequestW(HINTERNET request, LPCWSTR headers, DWORD headers_length, LPVOID optional, DWORD optional_length)
    {
        if (mrtw::hook_guard)
        {
            return real_HttpSendRequestW(request, headers, headers_length, optional, optional_length);
        }

        mrtw::HookGuard guard;
        BOOL result = real_HttpSendRequestW(request, headers, headers_length, optional, optional_length);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"HttpSendRequestW","pid":)" << mrtw::current_pid()
             << R"(,"headers_length":)" << headers_length
             << R"(,"optional_length":)" << optional_length
             << R"(,"result":)" << (result ? "true" : "false")
             << R"(,"last_error":)" << GetLastError()
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    int WSAAPI detour_connect(SOCKET socket, const sockaddr* name, int name_length)
    {
        if (mrtw::hook_guard)
        {
            return real_connect(socket, name, name_length);
        }

        std::string endpoint = socket_endpoint(name);
        mrtw::HookGuard guard;
        int result = real_connect(socket, name, name_length);
        int socket_error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"connect","pid":)" << mrtw::current_pid()
             << R"(,"endpoint":)" << mrtw::q(endpoint)
             << R"(,"address_family":)" << (name == nullptr ? 0 : name->sa_family)
             << R"(,"name_length":)" << name_length
             << R"(,"result":)" << result
             << R"(,"socket_error":)" << socket_error
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    int WSAAPI detour_WSAConnect(SOCKET socket, const sockaddr* name, int name_length, LPWSABUF caller_data, LPWSABUF callee_data, LPQOS sqos, LPQOS gqos)
    {
        if (mrtw::hook_guard)
        {
            return real_WSAConnect(socket, name, name_length, caller_data, callee_data, sqos, gqos);
        }

        std::string endpoint = socket_endpoint(name);
        mrtw::HookGuard guard;
        int result = real_WSAConnect(socket, name, name_length, caller_data, callee_data, sqos, gqos);
        int socket_error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WSAConnect","pid":)" << mrtw::current_pid()
             << R"(,"endpoint":)" << mrtw::q(endpoint)
             << R"(,"address_family":)" << (name == nullptr ? 0 : name->sa_family)
             << R"(,"name_length":)" << name_length
             << R"(,"result":)" << result
             << R"(,"socket_error":)" << socket_error
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    int WSAAPI detour_send(SOCKET socket, const char* buffer, int length, int flags)
    {
        if (mrtw::hook_guard)
        {
            return real_send(socket, buffer, length, flags);
        }

        mrtw::HookGuard guard;
        int result = real_send(socket, buffer, length, flags);
        int socket_error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"send","pid":)" << mrtw::current_pid()
             << R"(,"length":)" << length
             << R"(,"flags":)" << flags
             << R"(,"result":)" << result
             << R"(,"socket_error":)" << socket_error
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    int WSAAPI detour_WSASend(SOCKET socket, LPWSABUF buffers, DWORD buffer_count, LPDWORD bytes_sent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine)
    {
        if (mrtw::hook_guard)
        {
            return real_WSASend(socket, buffers, buffer_count, bytes_sent, flags, overlapped, completion_routine);
        }

        DWORD requested = 0;
        for (DWORD i = 0; buffers != nullptr && i < buffer_count; ++i)
        {
            requested += buffers[i].len;
        }

        mrtw::HookGuard guard;
        int result = real_WSASend(socket, buffers, buffer_count, bytes_sent, flags, overlapped, completion_routine);
        int socket_error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        std::ostringstream json;
        json << R"({"source":"hook","category":"Network","action":"WSASend","pid":)" << mrtw::current_pid()
             << R"(,"buffer_count":)" << buffer_count
             << R"(,"requested_bytes":)" << requested
             << R"(,"bytes_sent":)" << (bytes_sent == nullptr ? 0 : *bytes_sent)
             << R"(,"flags":)" << flags
             << R"(,"result":)" << result
             << R"(,"socket_error":)" << socket_error
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    DNS_STATUS WINAPI detour_DnsQuery_W(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDW* query_results, PVOID* reserved)
    {
        if (mrtw::hook_guard)
        {
            return real_DnsQuery_W(name, type, options, extra, query_results, reserved);
        }

        std::string query = mrtw::narrow(name);
        mrtw::HookGuard guard;
        DNS_STATUS status = real_DnsQuery_W(name, type, options, extra, query_results, reserved);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Dns","action":"DnsQuery_W","pid":)" << mrtw::current_pid()
             << R"(,"query":)" << mrtw::q(query)
             << R"(,"record_type":)" << type
             << R"(,"options":)" << options
             << R"(,"status":)" << status
             << "}";
        mrtw::emit_event(json.str());
        return status;
    }

    DNS_STATUS WINAPI detour_DnsQuery_A(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDA* query_results, PVOID* reserved)
    {
        if (mrtw::hook_guard)
        {
            return real_DnsQuery_A(name, type, options, extra, query_results, reserved);
        }

        std::string query = name == nullptr ? std::string{} : std::string(name);
        mrtw::HookGuard guard;
        DNS_STATUS status = real_DnsQuery_A(name, type, options, extra, query_results, reserved);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Dns","action":"DnsQuery_A","pid":)" << mrtw::current_pid()
             << R"(,"query":)" << mrtw::q(query)
             << R"(,"record_type":)" << type
             << R"(,"options":)" << options
             << R"(,"status":)" << status
             << "}";
        mrtw::emit_event(json.str());
        return status;
    }

    INT WSAAPI detour_GetAddrInfoW(PCWSTR node_name, PCWSTR service_name, const ADDRINFOW* hints, PADDRINFOW* result_info)
    {
        if (mrtw::hook_guard)
        {
            return real_GetAddrInfoW(node_name, service_name, hints, result_info);
        }

        std::string node = mrtw::narrow(node_name);
        std::string service = mrtw::narrow(service_name);
        mrtw::HookGuard guard;
        INT result = real_GetAddrInfoW(node_name, service_name, hints, result_info);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Dns","action":"GetAddrInfoW","pid":)" << mrtw::current_pid()
             << R"(,"node_name":)" << mrtw::q(node)
             << R"(,"service_name":)" << mrtw::q(service)
             << R"(,"family":)" << (hints == nullptr ? 0 : hints->ai_family)
             << R"(,"socktype":)" << (hints == nullptr ? 0 : hints->ai_socktype)
             << R"(,"protocol":)" << (hints == nullptr ? 0 : hints->ai_protocol)
             << R"(,"result":)" << result
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }

    INT WSAAPI detour_getaddrinfo(PCSTR node_name, PCSTR service_name, const ADDRINFOA* hints, PADDRINFOA* result_info)
    {
        if (mrtw::hook_guard)
        {
            return real_getaddrinfo(node_name, service_name, hints, result_info);
        }

        std::string node = node_name == nullptr ? std::string{} : std::string(node_name);
        std::string service = service_name == nullptr ? std::string{} : std::string(service_name);
        mrtw::HookGuard guard;
        INT result = real_getaddrinfo(node_name, service_name, hints, result_info);
        std::ostringstream json;
        json << R"({"source":"hook","category":"Dns","action":"getaddrinfo","pid":)" << mrtw::current_pid()
             << R"(,"node_name":)" << mrtw::q(node)
             << R"(,"service_name":)" << mrtw::q(service)
             << R"(,"family":)" << (hints == nullptr ? 0 : hints->ai_family)
             << R"(,"socktype":)" << (hints == nullptr ? 0 : hints->ai_socktype)
             << R"(,"protocol":)" << (hints == nullptr ? 0 : hints->ai_protocol)
             << R"(,"result":)" << result
             << "}";
        mrtw::emit_event(json.str());
        return result;
    }
}

namespace mrtw
{
    bool install_network_hooks()
    {
        LoadLibraryW(L"winhttp.dll");
        LoadLibraryW(L"wininet.dll");
        LoadLibraryW(L"ws2_32.dll");
        LoadLibraryW(L"dnsapi.dll");
        bool ok = true;
        ok &= MH_CreateHookApi(L"winhttp.dll", "WinHttpConnect", reinterpret_cast<LPVOID>(&detour_WinHttpConnect), reinterpret_cast<LPVOID*>(&real_WinHttpConnect)) == MH_OK;
        ok &= MH_CreateHookApi(L"winhttp.dll", "WinHttpOpenRequest", reinterpret_cast<LPVOID>(&detour_WinHttpOpenRequest), reinterpret_cast<LPVOID*>(&real_WinHttpOpenRequest)) == MH_OK;
        ok &= MH_CreateHookApi(L"winhttp.dll", "WinHttpSendRequest", reinterpret_cast<LPVOID>(&detour_WinHttpSendRequest), reinterpret_cast<LPVOID*>(&real_WinHttpSendRequest)) == MH_OK;
        ok &= MH_CreateHookApi(L"wininet.dll", "HttpOpenRequestW", reinterpret_cast<LPVOID>(&detour_HttpOpenRequestW), reinterpret_cast<LPVOID*>(&real_HttpOpenRequestW)) == MH_OK;
        ok &= MH_CreateHookApi(L"wininet.dll", "HttpSendRequestW", reinterpret_cast<LPVOID>(&detour_HttpSendRequestW), reinterpret_cast<LPVOID*>(&real_HttpSendRequestW)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "connect", reinterpret_cast<LPVOID>(&detour_connect), reinterpret_cast<LPVOID*>(&real_connect)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", reinterpret_cast<LPVOID>(&detour_WSAConnect), reinterpret_cast<LPVOID*>(&real_WSAConnect)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "send", reinterpret_cast<LPVOID>(&detour_send), reinterpret_cast<LPVOID*>(&real_send)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "WSASend", reinterpret_cast<LPVOID>(&detour_WSASend), reinterpret_cast<LPVOID*>(&real_WSASend)) == MH_OK;
        ok &= MH_CreateHookApi(L"dnsapi.dll", "DnsQuery_W", reinterpret_cast<LPVOID>(&detour_DnsQuery_W), reinterpret_cast<LPVOID*>(&real_DnsQuery_W)) == MH_OK;
        ok &= MH_CreateHookApi(L"dnsapi.dll", "DnsQuery_A", reinterpret_cast<LPVOID>(&detour_DnsQuery_A), reinterpret_cast<LPVOID*>(&real_DnsQuery_A)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "GetAddrInfoW", reinterpret_cast<LPVOID>(&detour_GetAddrInfoW), reinterpret_cast<LPVOID*>(&real_GetAddrInfoW)) == MH_OK;
        ok &= MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", reinterpret_cast<LPVOID>(&detour_getaddrinfo), reinterpret_cast<LPVOID*>(&real_getaddrinfo)) == MH_OK;
        emit_event(ok ? R"({"source":"hook","event":"network_hooks_installed"})" : R"({"source":"hook","event":"network_hooks_failed"})");
        return ok;
    }
}
