#pragma once

#include <string>
#include <vector>

// Central launcher log used for diagnostics and the UI status log.
// Thread-safe: may be called from background worker threads.

enum class LogLevel
{
    Info,
    Warning,
    Error
};

void LogAppend(LogLevel level, const std::string& message);

inline void LogInfo(const std::string& message) { LogAppend(LogLevel::Info, message); }
inline void LogWarn(const std::string& message) { LogAppend(LogLevel::Warning, message); }
inline void LogError(const std::string& message) { LogAppend(LogLevel::Error, message); }

std::vector<std::string> LogGetLines();
std::string LogGetText();
void LogClear();
void LogToClipboard();
