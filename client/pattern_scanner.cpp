#include "pattern_scanner.h"

#include <TlHelp32.h>
#include <cstring>
#include <sstream>

PatternScanner::PatternScanner(uint32_t pid, ReadMemoryFn read_fn)
    : pid_(pid), read_(std::move(read_fn)) {}

static bool parse_pattern_token(const std::string& token, uint8_t* byte, bool* wildcard)
{
    if (token == "?" || token == "??") {
        *wildcard = true;
        *byte = 0;
        return true;
    }

    *wildcard = false;
    char* end = nullptr;
    unsigned long value = strtoul(token.c_str(), &end, 16);
    if (end == token.c_str() || value > 0xFF)
        return false;

    *byte = static_cast<uint8_t>(value);
    return true;
}

std::optional<uint64_t> PatternScanner::FindPattern(
    ReadMemoryFn read_fn,
    uint32_t pid,
    uint64_t base,
    uint32_t size,
    const std::string& ida_pattern)
{
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;

    std::istringstream stream(ida_pattern);
    std::string token;
    while (stream >> token) {
        uint8_t b = 0;
        bool wild = false;
        if (!parse_pattern_token(token, &b, &wild))
            return std::nullopt;
        bytes.push_back(b);
        mask.push_back(wild);
    }

    if (bytes.empty() || size < bytes.size())
        return std::nullopt;

    std::vector<uint8_t> module_data(size);
    if (!read_fn(pid, base, module_data.data(), size))
        return std::nullopt;

    for (uint32_t i = 0; i <= size - bytes.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (!mask[j] && module_data[i + j] != bytes[j]) {
                match = false;
                break;
            }
        }
        if (match)
            return base + i;
    }

    return std::nullopt;
}

uint64_t PatternScanner::ResolveRipRelative(
    ReadMemoryFn read_fn,
    uint32_t pid,
    uint64_t match,
    int rip_offset,
    int instruction_size)
{
    int32_t rel = 0;
    if (!read_fn(pid, match + rip_offset, &rel, sizeof(rel)))
        return 0;

    return match + instruction_size + rel;
}

bool PatternScanner::Resolve(
    GameOffsets& out,
    const std::string& module_name,
    const std::string& pattern_uworld,
    const std::string& pattern_view_matrix,
    uint64_t hard_uworld,
    uint64_t hard_view_matrix)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32 mod{ sizeof(mod) };
    bool found_module = false;
    if (Module32First(snap, &mod)) {
        do {
            if (_stricmp(mod.szModule, module_name.c_str()) == 0) {
                out.module_base = reinterpret_cast<uint64_t>(mod.modBaseAddr);
                out.module_size = mod.modBaseSize;
                found_module = true;
                break;
            }
        } while (Module32Next(snap, &mod));
    }
    CloseHandle(snap);

    if (!found_module)
        return false;

    if (hard_uworld)
        out.uworld = out.module_base + hard_uworld;
    else if (!pattern_uworld.empty()) {
        auto match = FindPattern(read_, pid_, out.module_base, out.module_size, pattern_uworld);
        if (match)
            out.uworld = ResolveRipRelative(read_, pid_, *match, 3, 7);
    }

    if (hard_view_matrix)
        out.view_matrix = out.module_base + hard_view_matrix;
    else if (!pattern_view_matrix.empty()) {
        auto match = FindPattern(read_, pid_, out.module_base, out.module_size, pattern_view_matrix);
        if (match)
            out.view_matrix = ResolveRipRelative(read_, pid_, *match, 3, 7);
    }

    out.resolved = out.uworld != 0;
    return out.resolved;
}
