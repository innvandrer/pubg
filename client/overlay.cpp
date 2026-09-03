#include "overlay.h"

#include "ai_aimassist/aim_assist.h"
#include "ai_aimassist/defines.h"
#include <algorithm>
#include <dwmapi.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

Overlay::Overlay() = default;

Overlay::~Overlay()
{
    Shutdown();
}

bool Overlay::CreateOverlayWindow(const std::string& target_window_title)
{
    HWND target = FindWindowA(nullptr, target_window_title.c_str());
    if (!target)
        target = GetDesktopWindow();

    RECT rect{};
    GetWindowRect(target, &rect);
    width_ = rect.right - rect.left;
    height_ = rect.bottom - rect.top;

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "PubgMemVisOverlay";

    RegisterClassExA(&wc);

    hwnd_ = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
        wc.lpszClassName,
        "PubgMemVis",
        WS_POPUP,
        rect.left,
        rect.top,
        width_,
        height_,
        nullptr,
        nullptr,
        wc.hInstance,
        nullptr);

    if (!hwnd_)
        return false;

    MARGINS margins = { -1, -1, -1, -1 };
    DwmExtendFrameIntoClientArea(hwnd_, &margins);
    SetLayeredWindowAttributes(hwnd_, RGB(0, 0, 0), 255, LWA_ALPHA);

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);
    return true;
}

bool Overlay::CreateD3D11()
{
    DXGI_SWAP_CHAIN_DESC scd{};
    scd.BufferCount = 2;
    scd.BufferDesc.Width = width_;
    scd.BufferDesc.Height = height_;
    scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.OutputWindow = hwnd_;
    scd.SampleDesc.Count = 1;
    scd.Windowed = TRUE;
    scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL level{};
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0 };

    if (FAILED(D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            0,
            levels,
            1,
            D3D11_SDK_VERSION,
            &scd,
            &swap_chain_,
            &device_,
            &level,
            &context_)))
        return false;

    ID3D11Texture2D* back_buffer = nullptr;
    if (FAILED(swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer))))
        return false;

    device_->CreateRenderTargetView(back_buffer, nullptr, &rtv_);
    back_buffer->Release();
    return true;
}

void Overlay::DestroyD3D11()
{
    if (rtv_) { rtv_->Release(); rtv_ = nullptr; }
    if (swap_chain_) { swap_chain_->Release(); swap_chain_ = nullptr; }
    if (context_) { context_->Release(); context_ = nullptr; }
    if (device_) { device_->Release(); device_ = nullptr; }
}

bool Overlay::Initialize(const std::string& target_window_title)
{
    if (!CreateOverlayWindow(target_window_title))
        return false;
    if (!CreateD3D11())
        return false;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd_);
    ImGui_ImplDX11_Init(device_, context_);
    return true;
}

void Overlay::Shutdown()
{
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    DestroyD3D11();

    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

bool Overlay::ProcessMessages()
{
    MSG msg{};
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT)
            return false;
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return true;
}

void Overlay::BeginFrame()
{
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
}

void Overlay::SetViewMatrix(const float matrix[4][4])
{
    memcpy(view_matrix_, matrix, sizeof(view_matrix_));
}

bool Overlay::WorldToScreen(const Vector3& world, Vector2& screen) const
{
    const float w = view_matrix_[3][0] * world.x + view_matrix_[3][1] * world.y +
                    view_matrix_[3][2] * world.z + view_matrix_[3][3];
    if (w < 0.01f)
        return false;

    const float x = view_matrix_[0][0] * world.x + view_matrix_[0][1] * world.y +
                    view_matrix_[0][2] * world.z + view_matrix_[0][3];
    const float y = view_matrix_[1][0] * world.x + view_matrix_[1][1] * world.y +
                    view_matrix_[1][2] * world.z + view_matrix_[1][3];

    const float inv_w = 1.f / w;
    screen.x = (width_ * 0.5f) + (x * inv_w * width_ * 0.5f);
    screen.y = (height_ * 0.5f) - (y * inv_w * height_ * 0.5f);
    return screen.x >= 0 && screen.x <= width_ && screen.y >= 0 && screen.y <= height_;
}

void Overlay::Render(const std::vector<Player>& players, Config& config)
{
    if (config.show_menu) {
        ImGui::Begin("PUBG Memory Visualization", &config.show_menu);
        ImGui::Checkbox("ESP enabled", &config.esp_enabled);
        ImGui::Checkbox("Boxes", &config.esp_boxes);
        ImGui::Checkbox("Health bars", &config.esp_health_bar);
        ImGui::Checkbox("Names", &config.esp_names);
        ImGui::Checkbox("Distance", &config.esp_distance);
        ImGui::SliderFloat("Max distance", &config.esp_max_distance, 50.f, 2000.f);

        if (ImGui::CollapsingHeader("AI aim assist")) {
            ImGui::Checkbox("AI enabled", &config.ai_enabled);
            ImGui::Checkbox("Show AI detections", &config.ai_show_detections);
            ImGui::SliderInt("AI FOV size", &config.ai_fov_size, 50, AI_ACTIVATION_RANGE);
            ImGui::SliderFloat("AI smooth", &config.ai_smooth, 5.0f, 100.0f);
            ImGui::SliderFloat("AI aim height", &config.ai_aim_height, 1.0f, 100.0f);
            ImGui::SliderInt("AI scan FPS", &config.ai_scan_fps, 1, 250);
            ImGui::SliderFloat("AI confidence", &config.ai_confidence, 0.01f, 0.50f);
            ImGui::SliderFloat("AI NMS", &config.ai_nms_threshold, 0.05f, 0.90f);
            if (aim_assist_)
                ImGui::Text("AI backend: %s", aim_assist_->GetBackendName().c_str());
        }

        ImGui::Text("Keys: INSERT menu | F1 ESP | F2 health | F3 AI aim");
        ImGui::End();
    }

    if (!config.esp_enabled)
        return;

    ImDrawList* draw = ImGui::GetBackgroundDrawList();
    const ImU32 color = IM_COL32(config.esp_color_r, config.esp_color_g, config.esp_color_b, 255);

    for (const auto& player : players) {
        if (!player.is_alive)
            continue;

        Vector2 screen{};
        if (!WorldToScreen(player.pos, screen))
            continue;

        if (player.distance > config.esp_max_distance)
            continue;

        const float box_w = 40.f;
        const float box_h = 80.f;
        const ImVec2 top_left(screen.x - box_w * 0.5f, screen.y - box_h);
        const ImVec2 bottom_right(screen.x + box_w * 0.5f, screen.y);

        if (config.esp_boxes)
            draw->AddRect(top_left, bottom_right, color, 0.f, 0, 1.5f);

        if (config.esp_health_bar) {
            const float hp_ratio = player.max_health > 0.f
                ? std::clamp(player.health / player.max_health, 0.f, 1.f)
                : 0.f;
            const ImVec2 bar_tl(top_left.x - 6.f, top_left.y);
            const ImVec2 bar_br(top_left.x - 2.f, bottom_right.y);
            draw->AddRectFilled(bar_tl, bar_br, IM_COL32(40, 40, 40, 200));
            const float filled_h = (bottom_right.y - top_left.y) * hp_ratio;
            draw->AddRectFilled(
                ImVec2(bar_tl.x, bottom_right.y - filled_h),
                bar_br,
                IM_COL32(50, 205, 50, 255));
        }

        if (config.esp_names && !player.name.empty())
            draw->AddText(ImVec2(top_left.x, top_left.y - 16.f), IM_COL32(255, 255, 255, 255), player.name.c_str());

        if (config.esp_distance) {
            const std::string dist = std::to_string(static_cast<int>(player.distance)) + "m";
            draw->AddText(ImVec2(top_left.x, bottom_right.y + 2.f), IM_COL32(200, 200, 200, 255), dist.c_str());
        }
    }

    if (config.ai_enabled && aim_assist_) {
        const float cx = width_ * 0.5f;
        const float cy = height_ * 0.5f;
        const float radius = static_cast<float>(aim_assist_->GetFovSize());
        draw->AddCircle(ImVec2(cx, cy), radius, IM_COL32(255, 255, 255, 180), 64, 1.5f);

        if (config.ai_show_detections) {
            const auto boxes = aim_assist_->GetDetections();
            for (const auto& box : boxes) {
                draw->AddRect(
                    ImVec2(static_cast<float>(box.x), static_cast<float>(box.y)),
                    ImVec2(static_cast<float>(box.x + box.w), static_cast<float>(box.y + box.h)),
                    IM_COL32(255, 0, 0, 255), 0.f, 0, 2.f);
            }
        }
    }
}

void Overlay::EndFrame()
{
    ImGui::Render();
    const float clear[4] = { 0.f, 0.f, 0.f, 0.f };
    context_->OMSetRenderTargets(1, &rtv_, nullptr);
    context_->ClearRenderTargetView(rtv_, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    swap_chain_->Present(1, 0);
}
