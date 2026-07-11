#pragma once

#include <string>
#include <mutex>
#include <windows.h>

namespace mrtw
{
    class PipeClient
    {
    public:
        bool connect(const std::wstring& pipe_name);
        bool write_jsonl(const std::string& json);
        void close();

    private:
        HANDLE pipe_ = INVALID_HANDLE_VALUE;
        std::mutex mutex_;
    };
}
