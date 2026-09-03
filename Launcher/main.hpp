#pragma once

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "addons/imspinner.h"

#include "font/IconsFontAwesome6Brands.h"
#include "font/IconsFontAwesome6.h"
#include "font/MuseoSansRounded300.h"
#include "font/Museo700.h"
#include "font/trebucbd.h"

#include "texture/background.hpp"

#include <d3d11.h>

#include <windows.h>
#include <string> 
#include <stdio.h>
#include <tchar.h>
#include <dwmapi.h>

#include "winver/WinVersion.h"
VersionInfo info;

// Data
static ID3D11Device*            g_pd3dDevice = NULL;
static ID3D11DeviceContext*     g_pd3dDeviceContext = NULL;
static IDXGISwapChain*          g_pSwapChain = NULL;
static ID3D11RenderTargetView*  g_mainRenderTargetView = NULL;

using namespace std;

// Main window stuff
HWND hwnd;
RECT rc;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace Window
{
    const char*     ClassName       = "Class01";
    const char*     WindowName      = "Cleanest";
}

namespace Gui
{
	static ImVec2					Size            = { 900, 720 };
}
namespace var
{
    inline bool temp;
    inline bool prefetch;
    inline bool regedit;
    inline bool reloadEx;
    inline bool Safelaunch;
    inline bool CleanAClosing;
    inline bool JournalDelete;
    inline bool delexe;
    inline bool checking = false;
    inline bool clean = true; 
    inline bool driverBusy = false;
    inline std::string driverStatus = "Driver not loaded.";
    inline char driverPath[512] = "MyMemoryDriver.sys";
    inline int vulnDriverChoice = 0; // DriverLoader::VulnDriverChoice
    inline int kernelAllocMode = 0; // 0 = Pool, 1 = Independent Pages (KernelAllocMode)
    inline bool autoFallbackToScm = false;
    inline char targetPath[512] = "";
    inline bool hasTarget = false;

    inline char pubgConfigPath[512] = "config.json";
    inline std::string pubgStatus = "Load config and attach.";
    inline bool pubgBusy = false;

    // PUBG / Inject panel settings (mirrors Config fields, editable in UI)
    inline char injectProcessName[128] = "TslGame.exe";
    inline char injectAltProcessName[128] = "PUBG_BATTLEGROUNDS.exe";
    inline char injectWindowTitle[128] = "PUBG";
    inline char injectDriverPath[512] = "x64\\Release\\MyMemoryDriver.sys";
    inline int injectAppId = 578080;
    inline int injectTimeoutMs = 120000;
    inline bool injectCloseExisting = true;
    inline bool injectStopTerminatesGame = true;
    inline bool injectBusy = false;
    inline std::string injectStatus = "Press Inject to start the one-click PUBG flow.";
}
void UpdateWindowLocation() 
{
    GetWindowRect(hwnd, &rc);

    if (ImGui::GetWindowPos().x != 0 || ImGui::GetWindowPos().y != 0)
    {
        MoveWindow(hwnd,
                   rc.left + static_cast<int>(ImGui::GetWindowPos().x),
                   rc.top + static_cast<int>(ImGui::GetWindowPos().y),
                   static_cast<int>(Gui::Size.x),
                   static_cast<int>(Gui::Size.y),
                   TRUE);
        ImGui::SetWindowPos(ImVec2(0.f, 0.f));
    }
}

void RenderBlur(HWND hwnd)
{
    struct ACCENTPOLICY
    {
        int na;
        int nf;
        int nc;
        int nA;
    };
    struct WINCOMPATTRDATA
    {
        int na;
        PVOID pd;
        ULONG ul;
    };

    const HINSTANCE hm = LoadLibrary("user32.dll");
    if (hm)
    {
        typedef BOOL(WINAPI* pSetWindowCompositionAttribute)(HWND, WINCOMPATTRDATA*);

        const pSetWindowCompositionAttribute SetWindowCompositionAttribute = (pSetWindowCompositionAttribute)GetProcAddress(hm, "SetWindowCompositionAttribute");
        if (SetWindowCompositionAttribute)
        {
            ACCENTPOLICY policy = { 3, 0, 0, 0 };
            WINCOMPATTRDATA data = { 19, &policy,sizeof(ACCENTPOLICY) };
            SetWindowCompositionAttribute(hwnd, &data);
        }
        FreeLibrary(hm);
    }
}

ImFont* AddCustomDefaultFont(const ImFontConfig* font_cfg_template)
{
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    //ImFont* font = io.Fonts->AddFontFromMemoryCompressedTTF(trebucbd_compressed_data, trebucbd_compressed_size, font_cfg.SizePixels, &font_cfg, glyph_ranges);
    //ImFont* font = io.Fonts->AddFontFromMemoryCompressedTTF(&museo_700_binary, sizeof museo_700_binary, 12, nullptr, glyph_ranges);
    ImFont* font = io.Fonts->AddFontFromMemoryTTF(&museo_700_binary, sizeof museo_700_binary, 16, NULL, io.Fonts->GetGlyphRangesDefault());
    return font;
}