#include "pipe_client.h"

namespace mrtw
{
    bool PipeClient::connect(const std::wstring& pipe_name)
    {
        close();
        for (int attempt = 0; attempt < 30; ++attempt)
        {
            pipe_ = CreateFileW(
                pipe_name.c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (pipe_ != INVALID_HANDLE_VALUE)
            {
                return true;
            }

            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY)
            {
                break;
            }

            WaitNamedPipeW(pipe_name.c_str(), 100);
            Sleep(50);
        }

        return pipe_ != INVALID_HANDLE_VALUE;
    }

    bool PipeClient::write_jsonl(const std::string& json)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pipe_ == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        std::string line = json + "\n";
        DWORD written = 0;
        return WriteFile(pipe_, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) && written == line.size();
    }

    void PipeClient::close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pipe_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
        }
    }
}
