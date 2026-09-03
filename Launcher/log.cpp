#include "log.hpp"

#include <Windows.h>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <vector>

namespace
{
    std::mutex g_mutex;
    std::vector<std::string> g_lines;

    std::string ExeDirectory()
    {
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(nullptr, path, MAX_PATH))
            return {};

        const int len = WideCharToMultiByte(CP_ACP, 0, path, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0)
            return {};

        std::string narrow(static_cast<size_t>(len - 1), '\0');
        WideCharToMultiByte(CP_ACP, 0, path, -1, narrow.data(), len, nullptr, nullptr);

        const size_t pos = narrow.find_last_of("\\/");
        if (pos == std::string::npos)
            return {};
        narrow.resize(pos);
        return narrow;
    }

    std::string LogFilePath()
    {
        const std::string dir = ExeDirectory();
        if (dir.empty())
            return "launcher.log";
        return dir + "\\launcher.log";
    }

    std::string CurrentTimestamp()
    {
        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        struct tm local{};
        localtime_s(&local, &time);

        std::ostringstream ss;
        ss << '[' << std::setfill('0') << std::setw(2) << local.tm_hour << ':'
           << std::setw(2) << local.tm_min << ':' << std::setw(2) << local.tm_sec << ']';
        return ss.str();
    }

    char LevelTag(LogLevel level)
    {
        switch (level) {
        case LogLevel::Warning: return 'W';
        case LogLevel::Error:   return 'E';
        default:                return 'I';
        }
    }

    void WriteToFile(const std::string& line)
    {
        std::ofstream file(LogFilePath(), std::ios::app);
        if (file)
            file << line << '\n';
    }
}

void LogAppend(LogLevel level, const std::string& message)
{
    std::ostringstream ss;
    ss << CurrentTimestamp() << " [" << LevelTag(level) << "] " << message;
    const std::string line = ss.str();

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_lines.push_back(line);
        if (g_lines.size() > 500)
            g_lines.erase(g_lines.begin());
    }

    WriteToFile(line);
}

std::vector<std::string> LogGetLines()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_lines;
}

std::string LogGetText()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::string result;
    for (const auto& line : g_lines) {
        result += line;
        result += '\n';
    }
    return result;
}

void LogClear()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_lines.clear();
}

void LogToClipboard()
{
    const std::string text = LogGetText();
    if (text.empty())
        return;

    if (!OpenClipboard(nullptr))
        return;
    EmptyClipboard();

    const size_t len = text.size() + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (hMem) {
        memcpy(GlobalLock(hMem), text.c_str(), len);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }
    CloseClipboard();
}
