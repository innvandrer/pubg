#include "mouse_input.h"
#include <cstdint>

enum InjectedInputMouseOptions : ULONG {
    LEFT_DOWN = 0x0002,
    LEFT_UP = 0x0004,
    RIGHT_DOWN = 0x0008,
    RIGHT_UP = 0x0010,
};

struct InjectedInputMouseInfo {
    int32_t move_direction_x;
    int32_t move_direction_y;
    ULONG   mouse_options;
    ULONG   mouse_data;
    ULONG   timestamp;
    ULONG_PTR extra_info;
};

MouseInput::MouseInput() {
    HMODULE mod = LoadLibraryA("win32u.dll");
    if (mod)
        inject_ = (NtUserInjectMouseInputFn)GetProcAddress(mod, "NtUserInjectMouseInput");
}

MouseInput::~MouseInput() = default;

bool MouseInput::Inject(const void* info) const {
    if (!inject_)
        return false;
    return inject_(const_cast<void*>(info), 1) >= 0;
}

bool MouseInput::Move(int x, int y) {
    InjectedInputMouseInfo info{};
    info.move_direction_x = x;
    info.move_direction_y = y;
    return Inject(&info);
}

bool MouseInput::LeftDown(int x, int y) {
    InjectedInputMouseInfo info{};
    info.mouse_options = LEFT_DOWN;
    info.move_direction_x = x;
    info.move_direction_y = y;
    return Inject(&info);
}

bool MouseInput::LeftUp(int x, int y) {
    InjectedInputMouseInfo info{};
    info.mouse_options = LEFT_UP;
    info.move_direction_x = x;
    info.move_direction_y = y;
    return Inject(&info);
}
