#pragma once
#include <Windows.h>

class MouseInput {
public:
    MouseInput();
    ~MouseInput();

    bool Move(int x, int y);
    bool LeftDown(int x = 0, int y = 0);
    bool LeftUp(int x = 0, int y = 0);

private:
    bool Inject(const void* info) const;

    using NtUserInjectMouseInputFn = LONG(NTAPI*)(void* info, int count);
    NtUserInjectMouseInputFn inject_ = nullptr;
};
