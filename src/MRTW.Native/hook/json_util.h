#pragma once

#include <windows.h>

#include <sstream>
#include <string>

namespace mrtw
{
    inline std::string narrow(const wchar_t* value)
    {
        if (value == nullptr)
        {
            return {};
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
        {
            return {};
        }

        std::string output(static_cast<size_t>(required - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value, -1, output.data(), required, nullptr, nullptr);
        return output;
    }

    inline std::string narrow(const std::wstring& value)
    {
        return narrow(value.c_str());
    }

    inline std::string json_escape(const std::string& value)
    {
        std::ostringstream escaped;
        for (unsigned char ch : value)
        {
            switch (ch)
            {
            case '\\': escaped << "\\\\"; break;
            case '"': escaped << "\\\""; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (ch < 0x20)
                {
                    escaped << "\\u00";
                    constexpr char hex[] = "0123456789abcdef";
                    escaped << hex[(ch >> 4) & 0x0f] << hex[ch & 0x0f];
                }
                else
                {
                    escaped << ch;
                }
                break;
            }
        }

        return escaped.str();
    }

    inline std::string q(const std::string& value)
    {
        return "\"" + json_escape(value) + "\"";
    }

    inline DWORD current_pid()
    {
        return GetCurrentProcessId();
    }
}

