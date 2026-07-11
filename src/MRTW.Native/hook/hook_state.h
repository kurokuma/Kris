#pragma once

namespace mrtw
{
    inline thread_local bool hook_guard = false;

    class HookGuard
    {
    public:
        HookGuard() : previous_(hook_guard)
        {
            hook_guard = true;
        }

        ~HookGuard()
        {
            hook_guard = previous_;
        }

        HookGuard(const HookGuard&) = delete;
        HookGuard& operator=(const HookGuard&) = delete;

    private:
        bool previous_;
    };
}

