#pragma once

#include <Windows.h>
#include <stdio.h>
#include <time.h>

// #region agent log
inline void AgentDebugLogWritePath(const char* path, const char* hypothesisId, const char* location,
                                   const char* message, const char* dataJson, long long ts)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f)
        return;
    fprintf(f,
            "{\"sessionId\":\"c3c648\",\"runId\":\"pre-fix\",\"hypothesisId\":\"%s\","
            "\"location\":\"%s\",\"message\":\"%s\",\"data\":%s,\"timestamp\":%lld}\n",
            hypothesisId, location, message, dataJson ? dataJson : "{}", ts);
    fflush(f);
    fclose(f);
}

inline void AgentDebugLogClear()
{
    char logPath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    char* slash = strrchr(logPath, '\\');
    if (slash)
        *(slash + 1) = '\0';
    strcat_s(logPath, "debug-c3c648.log");
    DeleteFileA(logPath);
    DeleteFileA("Z:\\debug-c3c648.log");
    DeleteFileA("\\\\VBoxSvr\\loader_release\\debug-c3c648.log");
}

inline void AgentDebugLogWritePath722dd0(const char* path, const char* hypothesisId, const char* location,
                                          const char* message, const char* dataJson, long long ts)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f)
        return;
    fprintf(f,
            "{\"sessionId\":\"722dd0\",\"runId\":\"pre-fix\",\"hypothesisId\":\"%s\","
            "\"location\":\"%s\",\"message\":\"%s\",\"data\":%s,\"timestamp\":%lld}\n",
            hypothesisId, location, message, dataJson ? dataJson : "{}", ts);
    fflush(f);
    fclose(f);
}

inline void AgentDebugLog(const char* hypothesisId, const char* location, const char* message, const char* dataJson)
{
    char logPath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    char* slash = strrchr(logPath, '\\');
    if (slash)
        *(slash + 1) = '\0';
    strcat_s(logPath, "debug-c3c648.log");

    const long long ts = static_cast<long long>(time(nullptr)) * 1000;
    AgentDebugLogWritePath(logPath, hypothesisId, location, message, dataJson, ts);
    if (_strnicmp(logPath, "Z:\\", 3) != 0)
        AgentDebugLogWritePath("Z:\\debug-c3c648.log", hypothesisId, location, message, dataJson, ts);

    char log722[MAX_PATH]{};
    GetModuleFileNameA(nullptr, log722, MAX_PATH);
    slash = strrchr(log722, '\\');
    if (slash)
        *(slash + 1) = '\0';
    strcat_s(log722, "debug-722dd0.log");
    AgentDebugLogWritePath722dd0(log722, hypothesisId, location, message, dataJson, ts);
    AgentDebugLogWritePath722dd0("Z:\\debug-722dd0.log", hypothesisId, location, message, dataJson, ts);
}
// #endregion
