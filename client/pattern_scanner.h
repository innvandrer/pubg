#pragma once

#include <Windows.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

using ReadMemoryFn = std::function<bool(uint32_t pid, uint64_t address, void* buffer, size_t size)>;

struct GameOffsets {
    uint64_t module_base = 0;
    uint32_t module_size = 0;
    uint64_t uworld = 0;
    uint64_t view_matrix = 0;
    bool     resolved = false;
};

class PatternScanner {
public:
    PatternScanner(uint32_t pid, ReadMemoryFn read_fn);

    bool Resolve(GameOffsets& out, const std::string& module_name,
                 const std::string& pattern_uworld, const std::string& pattern_view_matrix,
                 uint64_t hard_uworld, uint64_t hard_view_matrix);

    static std::optional<uint64_t> FindPattern(
        ReadMemoryFn read_fn,
        uint32_t pid,
        uint64_t base,
        uint32_t size,
        const std::string& ida_pattern);

    static uint64_t ResolveRipRelative(
        ReadMemoryFn read_fn,
        uint32_t pid,
        uint64_t match,
        int rip_offset,
        int instruction_size);

private:
    uint32_t pid_;
    ReadMemoryFn read_;
};
