//============================================== ImGui Desktop ==============================================//
//
//   Dear ImGui: standalone example application for DirectX 11 - Desktop
//   If you are new to Dear ImGui, read documentation from the docs/ folder + read the top of imgui.cpp.
//   Read online: https://github.com/ocornut/imgui/tree/master/docs
// 
//===========================================================================================================//
#include "../font/EvolutionIconsQunion.h"
#include "../font/Montserrat-ExtraBold.h"

#include "../font/Montserrat-Medium.h"
#include "../font/Montserrat-Regular.h"
#include <Windows.h>
#include <strsafe.h>
#include <cstring>
#include <io.h>
#include <fcntl.h>
#include "main.hpp"
#include "newstuff/loader.hpp"
#include "client_panel.hpp"
#include "inject_thread.hpp"
#include "log.hpp"
#include <iostream>
#include <filesystem>
#include <thread>
#include <TlHelp32.h>
#include <iostream>
#include <commdlg.h>
#pragma comment(lib, "comdlg32.lib")
// Main code
ImFont* LexendDecaFont;
ImFont* IconFont;
ImFont* IconFontLogs;
ImFont* InterMedium;
ImFont* InterMediumone;
void CALLBACK hideConsole(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);

    KillTimer(NULL, idEvent);
}
void crash(const std::string& exe_path)
{
    // Legacy function neutralized; no action is performed.
    (void)exe_path;
    return;
   
    HWND hWnd = FindWindow("LWJGL", NULL); 
    if (!hWnd) {
        std::cout << "can't find minecraft process" << std::endl;
    
    }

    DWORD processId;
    GetWindowThreadProcessId(hWnd, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cout << "can't open minecraft process" << std::endl;
       
    }

   
    HANDLE hFile = CreateFile(exe_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open minecraft process" << std::endl;
     
    }

 
    DWORD dwFileSize = GetFileSize(hFile, NULL);


    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!lpBaseAddress) {
        std::cout << "Failed to allocate memory" << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
       
    }

  
    char* pBuffer = new char[dwFileSize];
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) {
        std::cout << "ailed to open minecraft process" << std::endl;
        delete[] pBuffer;
        VirtualFreeEx(hProcess, lpBaseAddress, dwFileSize, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        
    }

  
    if (!WriteProcessMemory(hProcess, lpBaseAddress, pBuffer, dwFileSize, NULL)) {
        std::cout << "Failed to write minecraft memory" << std::endl;
        delete[] pBuffer;
        VirtualFreeEx(hProcess, lpBaseAddress, dwFileSize, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        
    }

   
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, NULL);
    if (!hThread) {
        std::cout << "Failed to write minecraft memory" << std::endl;
        delete[] pBuffer;
        VirtualFreeEx(hProcess, lpBaseAddress, dwFileSize, MEM_RELEASE);
        CloseHandle(hFile);
        CloseHandle(hProcess);
        
    }

    
    WaitForSingleObject(hThread, INFINITE);

  //clean
    delete[] pBuffer;
    VirtualFreeEx(hProcess, lpBaseAddress, dwFileSize, MEM_RELEASE);
    CloseHandle(hFile);
    CloseHandle(hProcess);

}
HWND consoleWindow = GetConsoleWindow();
void searchRegistryKey(const std::string& exe_path, bool delete_keys, bool clean) {
      std::string exe_name = exe_path.substr(exe_path.find_last_of("\\/") + 1);
      std::transform(exe_name.begin(), exe_name.end(), exe_name.begin(), ::tolower);
            HKEY hKey;
      if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
          DWORD index = 0;
          TCHAR value_name[1024];
          DWORD value_name_size = sizeof(value_name);
          while (RegEnumValue(hKey, index, value_name, &value_name_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
              std::string key = std::string(value_name);
              std::transform(key.begin(), key.end(), key.begin(), ::tolower);
              if (key.find(exe_name) != std::string::npos) {
                  if (!delete_keys && !clean)
                  std::cout << "Regedit trace found: " << value_name << std::endl;
                  if (delete_keys) {
                      if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                          // Supprime la valeur de Registre
                          if (RegDeleteValue(hKey, value_name) == ERROR_SUCCESS) {
                       
                             std::cout << "Regedit trace deleted: SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store" << value_name << std::endl;
                          }
                          else {
                              printf("Error when deleting regedit trace.");
                          }
                          // Ferme la cl� de Registre
                          RegCloseKey(hKey);
                      }
                      else {
                          printf("unable to access regedits.");
                      }


                  }
              }
              index++;
              value_name_size = sizeof(value_name);
          }
          RegCloseKey(hKey);
      }
      else {
          std::cerr << "Failed to open registry key" << std::endl;
      }
  }


void searchFiles(const std::string& exe_path, bool delete_files, bool clean) {
    std::string exe_name = exe_path.substr(exe_path.find_last_of("\\/") + 1);
    std::transform(exe_name.begin(), exe_name.end(), exe_name.begin(), ::tolower);

    std::vector<std::string> directories = { "C:\\Windows\\Prefetch" };

    for (const auto& dir : directories) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            std::string file_name = entry.path().filename().string();
            std::transform(file_name.begin(), file_name.end(), file_name.begin(), ::tolower);
            if (file_name.find(exe_name) != std::string::npos) {
                if (!delete_files && !clean)
                std::cout << "Prefetch trace found: " << entry.path() << std::endl;
                if (delete_files) {
                    std::filesystem::remove(entry.path());
                    std::cout << "Trace deleted:" << entry.path() << std::endl;
                }
            }
        }
    }
}

void searchFiles2(const std::string& exe_path, bool delete_files, bool clean) {
    std::string exe_name = exe_path.substr(exe_path.find_last_of("\\/") + 1);
    std::transform(exe_name.begin(), exe_name.end(), exe_name.begin(), ::tolower);

    std::vector<std::string> directories = { "C:\\Windows\\Temp" };

    for (const auto& dir : directories) {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            std::string file_name = entry.path().filename().string();
            std::transform(file_name.begin(), file_name.end(), file_name.begin(), ::tolower);
            if (file_name.find(exe_name) != std::string::npos) {
                if (!delete_files && !clean)
                    std::cout << "Temp trace found: " << entry.path() << std::endl;
                
                
                if (delete_files ) {
                    std::filesystem::remove(entry.path());
                    std::cout << "Trace deleted:" << entry.path() << std::endl;
                }
            }
        }
    }
}

void reloadExp()
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);


    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (strcmp(entry.szExeFile, "explorer.exe") == 0)
            {
           
                HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                TerminateProcess(process, 0);
                CloseHandle(process);

               
                Sleep(1000);

               
                ShellExecute(NULL, "open", "explorer.exe", NULL, NULL, SW_SHOWNORMAL);

                break;
            }
        }
    }
    CloseHandle(snapshot);




}
bool launchAndWaitForProcess(const std::string& file_path) {
    STARTUPINFO startup_info = {};
    PROCESS_INFORMATION process_info = {};

    if (!CreateProcess(file_path.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info)) {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        return false;
    }

    bool process_finished = false;
    DWORD exit_code = 0;
    while (!process_finished) {
        if (GetExitCodeProcess(process_info.hProcess, &exit_code) && (exit_code != STILL_ACTIVE)) {
            process_finished = true;
        }
        Sleep(1000); 
    }

    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

    return true;
}
void clearjournal()
{

    std::string command = "fsutil usn deletejournal /d /n C:";

    
    int result = system(command.c_str());

  
    if (result != 0) {
        std::cout << "Failed to clear USN journal" << std::endl;
    }
    else {
        std::cout << "USN journal cleared successfully" << std::endl;
    }


}

void delexe(const std::string& file_path)
{


    if (DeleteFile(file_path.c_str())) {
        std::cout << "File deleted successfully." << std::endl;
    }
    else {
        std::cerr << "Error deleting file. Error code: " << GetLastError() << std::endl;
    }


}

void Function1(const std::string& search_term) {
    if (search_term.find("\\") != std::string::npos) {
      

      
  system("cls");
     
        searchFiles2(search_term, false, false);
        searchFiles(search_term, false, false);
        searchRegistryKey(search_term, false, false);

        SetTimer(NULL, 0, 3000, hideConsole);
      
   
      
    }
}

void Function(const std::string& search_term, bool clean) {
    if (search_term.find("\\") != std::string::npos) {
        system("cls");



      
            searchFiles2(search_term, var::temp, clean);
        searchFiles(search_term, var::prefetch, clean);
        searchRegistryKey(search_term, var::regedit, clean);

       

        SetTimer(NULL, 0, 3000, hideConsole);
      
   
 
    }
}
void launchProcessThread(const std::string& file_path) {
  
    bool result = launchAndWaitForProcess(file_path);
    ShowWindow(consoleWindow, SW_SHOW);
    if (result) {

      
       
       
      
        if (var::CleanAClosing)
        {
            Function(file_path, var::clean);
            if (var::reloadEx)
                reloadExp();

            if (var::JournalDelete)
                clearjournal();

            if (var::delexe)
                delexe(file_path);

            Sleep(3000);
            ShowWindow(consoleWindow, SW_HIDE);
        }

       

       

    }
}



std::string generateRandomTitle() {
    // rndm console name
    std::string title;
    const int titleLength = 8;
    const std::string characters = "abcdefghijklmnopqrstuvwxyz0123456789";
    const int charactersLength = static_cast<int>(characters.length());
    for (int i = 0; i < titleLength; i++) {
        title += characters[rand() % charactersLength];
    }
    return title;
}

bool SelectTargetFile(char* outPath, size_t outSize)
{
    char filename[MAX_PATH] = "";
    OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = "Select launch target (.exe)";
    if (GetOpenFileNameA(&ofn))
    {
        StringCbCopyA(outPath, outSize, filename);
        return true;
    }
    return false;
}

bool SelectDriverFile(char* outPath, size_t outSize)
{
    char filename[MAX_PATH] = "";
    OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Driver files (*.sys)\0*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = "Select kernel driver (.sys)";
    if (GetOpenFileNameA(&ofn))
    {
        StringCbCopyA(outPath, outSize, filename);
        return true;
    }
    return false;
}

static ImVec4 DriverStatusColor(const std::string& status)
{
    if (status.rfind("[+]", 0) == 0)
        return ImVec4(0.25f, 0.85f, 0.40f, 1.00f);
    if (status.rfind("[-]", 0) == 0)
        return ImVec4(0.95f, 0.35f, 0.35f, 1.00f);
    if (status.rfind("[*]", 0) == 0)
        return ImVec4(0.90f, 0.78f, 0.25f, 1.00f);
    return ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
}

static void DrawDriverStatusLine(const char* statusText, float wrapWidth)
{
    if (!statusText || !statusText[0])
        return;

    ImGui::PushStyleColor(ImGuiCol_Text, DriverStatusColor(statusText));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrapWidth);
    ImGui::TextWrapped("%s", statusText);
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("%s", statusText);
}

static void DrawStatusLog()
{
    for (const auto& line : LogGetLines()) {
        if (line.find("[E]") != std::string::npos)
            ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "%s", line.c_str());
        else if (line.find("[W]") != std::string::npos)
            ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.35f, 1.0f), "%s", line.c_str());
        else
            ImGui::TextUnformatted(line.c_str());
    }
}

static bool IsCliMode(int argc, char** argv)
{
    if (argc < 2 || !argv || !argv[1])
        return false;
    return _stricmp(argv[1], "load") == 0
        || _stricmp(argv[1], "ping") == 0
        || _stricmp(argv[1], "unload") == 0
        || _stricmp(argv[1], "--manual-map") == 0;
}

static bool StdHandleIsPipeOrFile(HANDLE handle)
{
    if (!handle || handle == INVALID_HANDLE_VALUE)
        return false;
    const DWORD type = GetFileType(handle);
    if (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK)
        return true;
    /* Some redirected handles (incl. VBox guestcontrol) report UNKNOWN. */
    return type == FILE_TYPE_UNKNOWN && GetLastError() == NO_ERROR;
}

static bool BindCrtToHandle(FILE* stream, HANDLE handle, const char* mode)
{
    if (!stream || !handle || handle == INVALID_HANDLE_VALUE)
        return false;

    HANDLE dup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(),
                         &dup, 0, TRUE, DUPLICATE_SAME_ACCESS))
        return false;

    const int srcFd = _open_osfhandle(reinterpret_cast<intptr_t>(dup), _O_TEXT);
    if (srcFd < 0)
    {
        CloseHandle(dup);
        return false;
    }

    /* WINDOWS subsystem: _fileno(stdout) is often -2. Give FILE a real fd. */
    if (_fileno(stream) < 0)
    {
        FILE* nul = nullptr;
        if (freopen_s(&nul, "NUL", mode, stream) != 0)
        {
            _close(srcFd);
            return false;
        }
    }

    const int dstFd = _fileno(stream);
    if (dstFd < 0 || _dup2(srcFd, dstFd) != 0)
    {
        _close(srcFd);
        return false;
    }
    _close(srcFd);
    setvbuf(stream, nullptr, _IONBF, 0);
    return true;
}

// Windows-subsystem binaries start with no CRT stdout. VBox guestcontrol and
// cmd.exe redirection pass pipes via STARTF_USESTDHANDLES — bind CRT to those
// handles and never AllocConsole (that steals printf away from the pipes).
// Otherwise attach the parent console, or AllocConsole as a last resort.
static void SetupCliStdio()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    const bool redirected = StdHandleIsPipeOrFile(hOut);

    if (redirected)
    {
        BindCrtToHandle(stdout, hOut, "w");
        BindCrtToHandle(stderr,
            StdHandleIsPipeOrFile(hErr) ? hErr : hOut, "w");
        std::ios::sync_with_stdio(true);
        std::cout.clear();
        std::cerr.clear();
        fflush(stdout);
        fflush(stderr);
        return;
    }

    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        AllocConsole();

    consoleWindow = GetConsoleWindow();
    FILE* fpOut = nullptr;
    FILE* fpErr = nullptr;
    FILE* fpIn = nullptr;
    freopen_s(&fpOut, "CONOUT$", "w", stdout);
    freopen_s(&fpErr, "CONOUT$", "w", stderr);
    freopen_s(&fpIn, "CONIN$", "r", stdin);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    std::ios::sync_with_stdio(true);
    if (consoleWindow)
        ShowWindow(consoleWindow, SW_SHOW);
}

static void SetupGuiHiddenConsole()
{
    AllocConsole();
    consoleWindow = GetConsoleWindow();
    FILE* fpOut = nullptr;
    FILE* fpErr = nullptr;
    freopen_s(&fpOut, "CONOUT$", "w", stdout);
    freopen_s(&fpErr, "CONOUT$", "w", stderr);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

namespace fs = std::filesystem;
int main(int argc, char* argv[]) 
{
    const bool cliMode = IsCliMode(argc, argv);
    if (cliMode)
        SetupCliStdio();
    else
        SetupGuiHiddenConsole();
    srand((unsigned)time(NULL));
    std::string title = generateRandomTitle();
    SetConsoleTitle(title.c_str());

    // Headless Manual Map for VM automation:
    //   Launcher.exe --manual-map C:\path\MyMemoryDriver.sys [--gdrv|--rtcore|--cpuz]
    if (argc >= 3 && _stricmp(argv[1], "--manual-map") == 0)
    {
        if (consoleWindow)
            ShowWindow(consoleWindow, SW_SHOW);
        auto vuln = IsWindows11_24H2OrLater()
            ? DriverLoader::VulnDriverChoice::RTCore64
            : DriverLoader::VulnDriverChoice::Gdrv;
        for (int i = 3; i < argc; ++i)
        {
            if (_stricmp(argv[i], "--rtcore") == 0)
                vuln = DriverLoader::VulnDriverChoice::RTCore64;
            else if (_stricmp(argv[i], "--cpuz") == 0)
                vuln = DriverLoader::VulnDriverChoice::Cpuz;
            else if (_stricmp(argv[i], "--gdrv") == 0)
                vuln = DriverLoader::VulnDriverChoice::Gdrv;
        }

        printf("[*] CLI --manual-map: %s via %s\n", argv[2], DriverLoader::VulnDriverChoiceLabel(vuln));
        fflush(stdout);
        std::string status;
        const bool ok = DriverLoader::LoadDriverManualMap(argv[2], vuln, KernelAllocMode::Pool, false, &status);
        printf("[*] CLI finished ok=%d status=%s\n", ok ? 1 : 0, status.c_str());
        fflush(stdout);
        Sleep(1500); // let mirrored Z:\ debug log flush
        return ok ? 0 : 1;
    }

    // Headless SCM commands for build automation:
    //   Launcher.exe load <path\MyMemoryDriver.sys>
    //   Launcher.exe ping
    //   Launcher.exe unload
    if (argc >= 3 && _stricmp(argv[1], "load") == 0)
    {
        if (consoleWindow)
            ShowWindow(consoleWindow, SW_SHOW);
        std::string status;
        const bool ok = DriverLoader::LoadDriverScm(argv[2], &status);
        printf("[*] CLI load finished ok=%d status=%s\n", ok ? 1 : 0, status.c_str());
        fflush(stdout);
        Sleep(1500);
        return ok ? 0 : 1;
    }
    if (argc >= 2 && _stricmp(argv[1], "ping") == 0)
    {
        if (consoleWindow)
            ShowWindow(consoleWindow, SW_SHOW);
        std::string status;
        const bool ok = DriverLoader::PingDriver(&status);
        printf("[*] CLI ping finished ok=%d status=%s\n", ok ? 1 : 0, status.c_str());
        fflush(stdout);
        Sleep(1500);
        return ok ? 0 : 1;
    }
    if (argc >= 2 && _stricmp(argv[1], "unload") == 0)
    {
        if (consoleWindow)
            ShowWindow(consoleWindow, SW_SHOW);
        std::string status;
        const bool ok = DriverLoader::UnloadDriver(&status);
        printf("[*] CLI unload finished ok=%d status=%s\n", ok ? 1 : 0, status.c_str());
        fflush(stdout);
        Sleep(1500);
        return ok ? 0 : 1;
    }

    // Hide the console window for normal GUI mode
    ShowWindow(consoleWindow, SW_HIDE);

    if (argc >= 2 && argv[1][0] != '\0' && argv[1][0] != '-') {
        StringCbCopyA(var::targetPath, sizeof(var::targetPath), argv[1]);
        var::hasTarget = true;
    }

    WNDCLASSEX windowClass = { };
    windowClass.cbSize = sizeof(WNDCLASSEX);
    windowClass.style = CS_CLASSDC;
    windowClass.lpfnWndProc = WndProc;
    windowClass.cbClsExtra = NULL;
    windowClass.cbWndExtra = NULL;
    windowClass.hInstance = GetModuleHandleA(0); // nullptr
    windowClass.hIcon = LoadIcon(0, IDI_APPLICATION);
    windowClass.hCursor = LoadCursor(0, IDC_ARROW);
    windowClass.hbrBackground = nullptr;
    windowClass.lpszMenuName = NULL;
    windowClass.lpszClassName = Window::ClassName;
    windowClass.hIconSm = LoadIcon(0, IDI_APPLICATION);

    RegisterClassEx(&windowClass);
    hwnd = CreateWindowEx(NULL, windowClass.lpszClassName, Window::WindowName, WS_POPUP | CW_USEDEFAULT,
                          (GetSystemMetrics(SM_CXSCREEN) / 2) - static_cast<int>(Gui::Size.x / 2),
                          (GetSystemMetrics(SM_CYSCREEN) / 2) - static_cast<int>(Gui::Size.y / 2),
                          static_cast<int>(Gui::Size.x),
                          static_cast<int>(Gui::Size.y),
                          0, 0, 0, 0);

    SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);

    MARGINS margins = { -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    rc = { 0 };
    GetWindowRect(hwnd, &rc);

    //RenderBlur(hwnd);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClass(windowClass.lpszClassName, windowClass.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Getting some shutdown stuff
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    io.IniFilename = NULL; // Remove the imgui.ini

    ImGui::StyleColorsDark();

    ImGuiStyle& style = ImGui::GetStyle();

    style.WindowRounding = 10;
    style.Colors[ImGuiCol_Text] = ImVec4(0.90f, 0.90f, 0.94f, 1.00f);

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    AddCustomDefaultFont(nullptr);

    // merge in icons from Font Awesome
    static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_16_FA, 0 };
    static const ImWchar icons_ranges_brands[] = { ICON_MIN_FAB, ICON_MAX_16_FAB, 0 };
    ImFontConfig icons_config;
    IconFont = io.Fonts->AddFontFromMemoryTTF(Icons, sizeof(Icons), 23, NULL, io.Fonts->GetGlyphRangesCyrillic());
    IconFontLogs = io.Fonts->AddFontFromMemoryTTF(IconFontLog, sizeof(IconFontLog), 25, NULL, io.Fonts->GetGlyphRangesCyrillic());
    LexendDecaFont = io.Fonts->AddFontFromMemoryTTF(LexendDeca, sizeof(LexendDeca), 22, NULL, io.Fonts->GetGlyphRangesCyrillic());
    //InterMedium = io.Fonts->AddFontFromMemoryTTF(Intermedium, sizeof(Intermedium), 17, NULL, io.Fonts->GetGlyphRangesCyrillic());

    InterMediumone = io.Fonts->AddFontFromMemoryTTF(Intermedium, sizeof(Intermedium), 14, NULL, io.Fonts->GetGlyphRangesCyrillic());
    // Main loop
    bool loaderOpen = true;
    if (WinVersion::GetVersion(info) && info.BuildNum >= 26100)
    {
        var::vulnDriverChoice = 1; // RTCore64
        printf("[*] Windows 11 24H2+ (build %lu) detected: defaulting BYOVD to RTCore64.\n", info.BuildNum);
    }

    if (WinVersion::GetVersion(info) && info.Major <= 6)
    {
        MessageBox(hwnd, "your operating system is not supported", "Error", MB_ICONERROR);
    }
    else while ( loaderOpen && (info.Major > 6) )
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
            {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
        if (!loaderOpen)
        {
            break;
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        {std::string file_path = var::targetPath;
            ImGuiWindowFlags main_window_flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
            ImGui::SetNextWindowPos({0 , 0}, ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(Gui::Size);

            ImGui::Begin(Window::WindowName, &loaderOpen, main_window_flags); {
                UpdateWindowLocation();
                const float panelWidth = 430.f;
                const float panelHeight = ImGui::GetContentRegionAvail().y;
                const ImGuiWindowFlags panelFlags = ImGuiWindowFlags_NoScrollbar;
                {ImGui::BeginGroup();
                {
                    ImGui::BeginChild("Process Launcher", ImVec2(panelWidth, panelHeight), false, panelFlags);
                    {
                        const float contentWidth = ImGui::GetContentRegionAvail().x;
                        const float statusBoxHeight = 120.f;
                        const float statusFooterReserve =
                            ImGui::GetTextLineHeightWithSpacing() * 3.f + statusBoxHeight +
                            ImGui::GetStyle().ItemSpacing.y * 3.f;

                        const ImVec4 sectionHeaderColor = ImVec4(0.39f, 0.78f, 1.00f, 1.00f);
                        const bool driverLoaded = DriverLoader::IsDriverLoaded();

                        static int leftTab = 0;
                        if (ImGui::BeginTabBar("leftTabs", ImGuiTabBarFlags_None))
                        {
                            if (ImGui::BeginTabItem("Launch"))
                            {
                                leftTab = 0;
                                ImGui::EndTabItem();
                            }
                            if (ImGui::BeginTabItem("Driver"))
                            {
                                leftTab = 1;
                                ImGui::EndTabItem();
                            }
                            if (ImGui::BeginTabItem("PUBG"))
                            {
                                leftTab = 2;
                                ImGui::EndTabItem();
                            }
                            ImGui::EndTabBar();
                        }

                        ImGui::BeginChild("leftContent", ImVec2(contentWidth, -statusFooterReserve), true);
                        {
                        const float innerWidth = ImGui::GetContentRegionAvail().x;
                        const float halfBtnWidth =
                            (innerWidth - ImGui::GetStyle().ItemSpacing.x) * 0.5f;

                        // Keep inject state current even when another left tab is selected.
                        var::injectBusy = IsInjectBusy();
                        var::injectStatus = GetInjectStatus();

                        if (leftTab == 0)
                        {
                        ImGui::TextColored(sectionHeaderColor, "Process Launcher");
                        ImGui::TextDisabled("Userland .exe to launch with Safe launch.");
                        ImGui::Spacing();

                        if (ImGui::Button("Select launch target (.exe)...", ImVec2(innerWidth, 24)))
                        {
                            if (SelectTargetFile(var::targetPath, sizeof(var::targetPath)))
                                var::hasTarget = true;
                        }
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Pick the executable to run — not your kernel .sys driver.");
                        ImGui::TextDisabled("Launch target");
                        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + innerWidth);
                        ImGui::TextUnformatted(var::hasTarget ? var::targetPath : "(none — use Select above)");
                        ImGui::PopTextWrapPos();
                        ImGui::Spacing();
                        ImGui::Separator();
                        ImGui::Spacing();

                        ImGui::TextDisabled("Launch options");
                        ImGui::Checkbox("Clean after closing", &var::CleanAClosing);
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Run selected cleaner tasks when the launched process exits.");
                        ImGui::Checkbox("Reload explorer.exe after closing", &var::reloadEx);
                        ImGui::Spacing();
                        if (ImGui::Button("Safe launch", ImVec2(innerWidth, 30)))
                        {
                            if (!var::hasTarget)
                                var::driverStatus = "[-] Select a launch target (.exe) first.";
                            else
                            {
                                std::thread process_thread(launchProcessThread, file_path);
                                process_thread.detach();
                            }
                        }
                        if (!var::hasTarget && ImGui::IsItemHovered())
                            ImGui::SetTooltip("Select a launch target (.exe) first.");
                        }

                        else if (leftTab == 1)
                        {
                        ImGui::TextColored(sectionHeaderColor, "Kernel Driver");
                        ImGui::TextDisabled("Your .sys driver — separate from the launch target above.");
                        ImGui::Spacing();

                        if (ImGui::Button("Select driver file...", ImVec2(innerWidth, 24)))
                            SelectDriverFile(var::driverPath, sizeof(var::driverPath));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Pick a kernel driver (.sys) — separate from the launch target .exe.");
                        ImGui::TextDisabled("Driver path (.sys)");
                        ImGui::SetNextItemWidth(-1.f);
                        ImGui::InputText("##driverPath", var::driverPath, sizeof(var::driverPath));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Kernel driver file (.sys), not the userland .exe.\nFilename or full path. Also checks .\\drivers\\, ..\\drivers\\, Desktop\\Drivers.");

                        const char* vulnDrivers[] = {
                            DriverLoader::VulnDriverChoiceLabel(DriverLoader::VulnDriverChoice::Gdrv),
                            DriverLoader::VulnDriverChoiceLabel(DriverLoader::VulnDriverChoice::RTCore64),
                            DriverLoader::VulnDriverChoiceLabel(DriverLoader::VulnDriverChoice::Dbutil),
                            DriverLoader::VulnDriverChoiceLabel(DriverLoader::VulnDriverChoice::Cpuz)
                        };
                        ImGui::TextDisabled("BYOVD provider");
                        ImGui::SetNextItemWidth(-1.f);
                        ImGui::Combo("##vulnDriver", &var::vulnDriverChoice, vulnDrivers, IM_ARRAYSIZE(vulnDrivers));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Used by Load (Manual Map) only.");

                        const char* allocModes[] = { "Pool", "Independent Pages" };
                        ImGui::TextDisabled("Allocation mode");
                        ImGui::SetNextItemWidth(-1.f);
                        ImGui::Combo("##kernelAllocMode", &var::kernelAllocMode, allocModes, IM_ARRAYSIZE(allocModes));
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Pool is the default. Independent Pages is stealthier but only available on recent Windows builds.");

                        ImGui::Checkbox("Auto-fallback to SCM on manual-map failure", &var::autoFallbackToScm);
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("If manual map fails (e.g. gdrv on 24H2), automatically try the SCM loader.");

                        const bool hasDriverPath = var::driverPath[0] != '\0';
                        const bool driverLoadInProgress = var::driverBusy;

                        if (driverLoadInProgress)
                            ImGui::BeginDisabled();

                        if (ImGui::Button("Load (Manual Map)", ImVec2(halfBtnWidth, 24)))
                        {
                            if (!hasDriverPath)
                                var::driverStatus = "[-] Enter a driver .sys path first.";
                            else
                            {
                                var::driverBusy = true;
                                var::driverStatus = "[*] Manual mapping driver...";
                                std::string pathStr(var::driverPath);
                                const auto vuln = static_cast<DriverLoader::VulnDriverChoice>(var::vulnDriverChoice);
                                const auto mode = static_cast<KernelAllocMode>(var::kernelAllocMode);
                                const bool fallback = var::autoFallbackToScm;
                                std::thread([pathStr, vuln, mode, fallback]() {
                                    struct LoadGuard { ~LoadGuard() { var::driverBusy = false; } } guard;
                                    DriverLoader::LoadDriverManualMap(pathStr, vuln, mode, fallback, &var::driverStatus);
                                }).detach();
                            }
                        }
                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        {
                            if (driverLoadInProgress)
                                ImGui::SetTooltip("Driver load in progress...");
                            else if (!hasDriverPath)
                                ImGui::SetTooltip("Enter a driver .sys path first.");
                        }
                        ImGui::SameLine();
                        if (ImGui::Button("Load (SCM)", ImVec2(halfBtnWidth, 24)))
                        {
                            if (!hasDriverPath)
                                var::driverStatus = "[-] Enter a driver .sys path first.";
                            else
                            {
                                var::driverBusy = true;
                                var::driverStatus = "[*] Loading driver via SCM...";
                                std::string pathStr(var::driverPath);
                                std::thread([pathStr]() {
                                    struct LoadGuard { ~LoadGuard() { var::driverBusy = false; } } guard;
                                    DriverLoader::LoadDriverScm(pathStr, &var::driverStatus);
                                }).detach();
                            }
                        }
                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        {
                            if (driverLoadInProgress)
                                ImGui::SetTooltip("Driver load in progress...");
                            else if (!hasDriverPath)
                                ImGui::SetTooltip("Enter a driver .sys path first.");
                        }

                        if (driverLoadInProgress)
                            ImGui::EndDisabled();

                        if (ImGui::Button("Unload driver", ImVec2(halfBtnWidth, 24)))
                        {
                            if (var::driverBusy)
                                var::driverStatus = "[*] Driver operation already in progress.";
                            else if (!driverLoaded)
                                var::driverStatus = "[-] No driver loaded to unload.";
                            else
                            {
                                var::driverBusy = true;
                                var::driverStatus = "[*] Unloading driver...";
                                std::thread([]() {
                                    DriverLoader::UnloadDriver(&var::driverStatus);
                                    var::driverBusy = false;
                                }).detach();
                            }
                        }
                        if (!driverLoaded && ImGui::IsItemHovered())
                            ImGui::SetTooltip("Load a driver first.");
                        ImGui::SameLine();
                        if (ImGui::Button("Ping driver", ImVec2(halfBtnWidth, 24)))
                        {
                            if (var::driverBusy)
                                var::driverStatus = "[*] Driver operation already in progress.";
                            else if (!driverLoaded)
                                var::driverStatus = "[-] Load a driver first, then ping.";
                            else
                            {
                                var::driverBusy = true;
                                var::driverStatus = "[*] Pinging driver...";
                                std::thread([]() {
                                    DriverLoader::PingDriver(&var::driverStatus);
                                    var::driverBusy = false;
                                }).detach();
                            }
                        }
                        if (!driverLoaded && ImGui::IsItemHovered())
                            ImGui::SetTooltip("Load a driver first, then ping its device.");
                        }

                        else
                        {
                            ImGui::TextColored(sectionHeaderColor, "PUBG Client");
                            ImGui::TextDisabled("config.json / attach / overlay / one-click inject");
                            ImGui::Spacing();

                            if (ImGui::BeginTabBar("pubgTabs", ImGuiTabBarFlags_None))
                            {
                                if (ImGui::BeginTabItem("Manual"))
                                {
                                    const float tabWidth = ImGui::GetContentRegionAvail().x;
                                    const float tabHalfBtnWidth =
                                        (tabWidth - ImGui::GetStyle().ItemSpacing.x) * 0.5f;

                                    if (var::pubgBusy || PUBGPanelIsOverlayRunning() || var::injectBusy)
                                        ImGui::BeginDisabled();

                                    if (ImGui::Button("Load config", ImVec2(tabHalfBtnWidth, 24)))
                                    {
                                        std::string path(var::pubgConfigPath);
                                        std::thread([path]() {
                                            std::string status;
                                            PUBGPanelLoadConfig(path, &status);
                                            var::pubgStatus = status;
                                        }).detach();
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Load config.json for the overlay/aim-assist module.");

                                    ImGui::SameLine();
                                    if (ImGui::Button("Attach", ImVec2(tabHalfBtnWidth, 24)))
                                    {
                                        var::pubgBusy = true;
                                        std::thread([]() {
                                            std::string status;
                                            PUBGPanelAttach(&status);
                                            var::pubgStatus = status;
                                            var::pubgBusy = false;
                                        }).detach();
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Verify the game process is reachable through the loaded driver.");

                                    if (var::pubgBusy || PUBGPanelIsOverlayRunning() || var::injectBusy)
                                        ImGui::EndDisabled();

                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputText("##pubgConfigPath", var::pubgConfigPath, sizeof(var::pubgConfigPath));

                                    const bool canLaunch = DriverLoader::IsDriverLoaded() && !var::pubgBusy && !PUBGPanelIsOverlayRunning() && !var::injectBusy;
                                    if (!canLaunch)
                                        ImGui::BeginDisabled();
                                    if (ImGui::Button("Launch overlay", ImVec2(tabWidth, 24)))
                                    {
                                        std::string status;
                                        if (PUBGPanelLaunchOverlay(&status))
                                            var::pubgStatus = status;
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Launch the ESP/AI overlay in a separate window.");
                                    if (!canLaunch)
                                        ImGui::EndDisabled();

                                    ImGui::TextDisabled("%s", var::pubgStatus.c_str());
                                    ImGui::EndTabItem();
                                }

                                if (ImGui::BeginTabItem("Inject"))
                                {
                                    const bool injectRunning = var::injectBusy || IsInjectRunning();
                                    const float tabWidth = ImGui::GetContentRegionAvail().x;
                                    const float tabHalfBtnWidth =
                                        (tabWidth - ImGui::GetStyle().ItemSpacing.x) * 0.5f;

                                    if (ImGui::Button("Load config", ImVec2(tabHalfBtnWidth, 24)))
                                    {
                                        std::string path(var::pubgConfigPath);
                                        std::thread([path]() {
                                            std::string status;
                                            Config cfg;
                                            if (cfg.Load(path)) {
                                                status = "[+] Config loaded for inject.";
                                                var::injectAppId = cfg.inject_steam_appid;
                                                strncpy_s(var::injectProcessName, cfg.inject_process_name.c_str(), sizeof(var::injectProcessName) - 1);
                                                strncpy_s(var::injectAltProcessName, cfg.inject_alt_process_name.c_str(), sizeof(var::injectAltProcessName) - 1);
                                                strncpy_s(var::injectWindowTitle, cfg.inject_window_title.c_str(), sizeof(var::injectWindowTitle) - 1);
                                                strncpy_s(var::injectDriverPath, cfg.inject_driver_path.c_str(), sizeof(var::injectDriverPath) - 1);
                                                var::injectTimeoutMs = cfg.inject_launch_timeout_ms;
                                                var::injectCloseExisting = cfg.inject_close_existing;
                                                var::injectStopTerminatesGame = cfg.inject_stop_terminates_game;
                                            } else {
                                                status = "[-] Failed to load config.json.";
                                            }
                                            var::injectStatus = status;
                                        }).detach();
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Load config.json and populate the inject settings.");

                                    ImGui::SameLine();
                                    if (injectRunning)
                                        ImGui::BeginDisabled();
                                    if (ImGui::Button("Inject", ImVec2(tabHalfBtnWidth, 24)))
                                    {
                                        Config cfg;
                                        if (!cfg.Load(var::pubgConfigPath)) {
                                            var::injectStatus = "[-] Load config.json first.";
                                        } else {
                                            cfg.inject_steam_appid = var::injectAppId;
                                            cfg.inject_process_name = var::injectProcessName;
                                            cfg.inject_alt_process_name = var::injectAltProcessName;
                                            cfg.inject_window_title = var::injectWindowTitle;
                                            cfg.inject_driver_path = var::injectDriverPath;
                                            cfg.inject_launch_timeout_ms = var::injectTimeoutMs;
                                            cfg.inject_close_existing = var::injectCloseExisting;
                                            cfg.inject_stop_terminates_game = var::injectStopTerminatesGame;

                                            InjectSettings settings;
                                            settings.config = cfg;
                                            settings.driverPath = var::driverPath[0] ? var::driverPath : var::injectDriverPath;
                                            settings.vulnDriver = static_cast<DriverLoader::VulnDriverChoice>(var::vulnDriverChoice);
                                            settings.kernelAllocMode = static_cast<KernelAllocMode>(var::kernelAllocMode);
                                            settings.autoFallbackToScm = var::autoFallbackToScm;

                                            const std::string prereqs = CheckInjectPrerequisites(settings);
                                            if (!prereqs.empty()) {
                                                LogWarn(prereqs);
                                                var::injectStatus = "[*] Prerequisite warnings logged; see status log.";
                                            }

                                            StartInjectThread(settings);
                                        }
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Close/relaunch PUBG via Steam, load the driver, and start the overlay.");
                                    if (injectRunning)
                                        ImGui::EndDisabled();

                                    if (!injectRunning)
                                        ImGui::BeginDisabled();
                                    if (ImGui::Button("Stop / Detach", ImVec2(tabWidth, 24)))
                                    {
                                        StopInjectThread(var::injectStopTerminatesGame);
                                    }
                                    if (ImGui::IsItemHovered())
                                        ImGui::SetTooltip("Stop the overlay and optionally terminate the game.");
                                    if (!injectRunning)
                                        ImGui::EndDisabled();

                                    ImGui::TextDisabled("Process name");
                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputText("##injectProcessName", var::injectProcessName, sizeof(var::injectProcessName));
                                    ImGui::TextDisabled("Alt process name");
                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputText("##injectAltProcessName", var::injectAltProcessName, sizeof(var::injectAltProcessName));
                                    ImGui::TextDisabled("Window title");
                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputText("##injectWindowTitle", var::injectWindowTitle, sizeof(var::injectWindowTitle));

                                    ImGui::TextDisabled("Steam AppID");
                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputInt("##injectAppId", &var::injectAppId);
                                    ImGui::TextDisabled("Launch timeout (ms)");
                                    ImGui::SetNextItemWidth(-1.f);
                                    ImGui::InputInt("##injectTimeoutMs", &var::injectTimeoutMs);

                                    ImGui::Checkbox("Close existing game before launch", &var::injectCloseExisting);
                                    ImGui::Checkbox("Stop terminates game", &var::injectStopTerminatesGame);

                                    ImGui::TextDisabled("%s", var::injectStatus.c_str());
                                    ImGui::EndTabItem();
                                }
                                ImGui::EndTabBar();
                            }
                        }
                        } ImGui::EndChild();

                        if (driverLoaded)
                            ImGui::TextDisabled("Active load method: %s", DriverLoader::GetLoadMethodLabel());

                        ImGui::TextDisabled("Status log");
                        ImGui::SameLine();
                        ImGui::Dummy(ImVec2(contentWidth - ImGui::GetCursorPosX() - 60.f, 0.f));
                        ImGui::SameLine();
                        if (ImGui::Button("Copy log", ImVec2(60.f, 18.f)))
                        {
                            LogToClipboard();
                        }
                        if (ImGui::IsItemHovered())
                            ImGui::SetTooltip("Copy the full status log to the clipboard.");

                        ImGui::BeginChild("driverStatus", ImVec2(contentWidth, statusBoxHeight), true,
                                          ImGuiWindowFlags_AlwaysVerticalScrollbar);
                        DrawStatusLog();
                        ImGui::EndChild();

                    }ImGui::EndChild();
                }ImGui::EndGroup();


                ImGui::SameLine();
                ImGui::BeginGroup();
                {

                    ImGui::BeginChild("Cleaner settings", ImVec2(panelWidth, panelHeight), false, panelFlags);
                    {
                        const float contentWidth = ImGui::GetContentRegionAvail().x;

                        ImGui::TextColored(ImVec4(0.39f, 0.78f, 1.00f, 1.00f), "Trace Cleaner");
                        ImGui::TextDisabled("Remove forensic traces for the launch target.");
                        ImGui::Spacing();

                        ImGui::Checkbox("Delete .exe", &var::delexe);
                        ImGui::Checkbox("Clean prefetch", &var::prefetch);
                        ImGui::Checkbox("Clean regedit", &var::regedit);
                        ImGui::Checkbox("Clean temp", &var::temp);
                        ImGui::Checkbox("Clean modification logs", &var::JournalDelete);

                        ImGui::Spacing();
                        ImGui::Spacing();
                        if (ImGui::Button("Clean", ImVec2(contentWidth, 30)))
                        {
                            if (!var::hasTarget)
                                var::driverStatus = "[-] Select a launch target (.exe) first.";
                            else
                            {
                                ShowWindow(consoleWindow, SW_SHOW);

                                if (var::JournalDelete)
                                    clearjournal();

                                if (var::delexe)
                                    delexe(file_path);

                                Function(file_path, var::clean);
                            }
                        }
                        if (!var::hasTarget && ImGui::IsItemHovered())
                            ImGui::SetTooltip("Select a launch target (.exe) on the left first.");

                        if (ImGui::Button("Reload explorer.exe", ImVec2(contentWidth, 30)))
                            reloadExp();

                        if (ImGui::Button("Check traces", ImVec2(contentWidth, 30)))
                        {
                            if (!var::hasTarget)
                                var::driverStatus = "[-] Select a launch target (.exe) first.";
                            else
                            {
                                var::checking = true;
                                ShowWindow(consoleWindow, SW_SHOW);
                                Function1(file_path);
                            }
                        }
                        if (!var::hasTarget && ImGui::IsItemHovered())
                            ImGui::SetTooltip("Select a launch target (.exe) on the left first.");

                    }ImGui::EndChild();
                }
                ImGui::EndGroup();
                }
            }
            ImGui::End();
        }

        // Rendering
        ImGui::Render();
       
        const float clear_color_with_alpha[4] = { 0 };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // Never set the 1 to 0 or the panel movment will get fucked
    }

    // Cleanup
    // Stop any long-running PUBG threads before tearing down D3D/ImGui.
    PUBGPanelStopOverlay(nullptr, 5000);
    StopInjectThread(false);

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(windowClass.lpszClassName, windowClass.hInstance);

    return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
    // Setup swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}