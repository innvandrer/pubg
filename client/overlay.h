#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <string>
#include <vector>

#include "config.h"

struct Vector2 { float x = 0.f, y = 0.f; };
struct Vector3 { float x = 0.f, y = 0.f, z = 0.f; };

class AimAssist;

struct Player {
    Vector3 pos{};
    float health = 100.f;
    float max_health = 100.f;
    bool is_alive = true;
    std::string name;
    float distance = 0.f;
};

class Overlay {
public:
    Overlay();
    ~Overlay();

    bool Initialize(const std::string& target_window_title);
    void Shutdown();

    bool ProcessMessages();
    void BeginFrame();
    void Render(const std::vector<Player>& players, Config& config);
    void EndFrame();

    void SetViewMatrix(const float matrix[4][4]);

    bool WorldToScreen(const Vector3& world, Vector2& screen) const;

    void SetAimAssist(AimAssist* aim) { aim_assist_ = aim; }

    [[nodiscard]] int GetWidth() const { return width_; }
    [[nodiscard]] int GetHeight() const { return height_; }
    [[nodiscard]] HWND GetHwnd() const { return hwnd_; }

private:
    AimAssist* aim_assist_ = nullptr;
    bool CreateOverlayWindow(const std::string& target_window_title);
    bool CreateD3D11();
    void DestroyD3D11();

    HWND hwnd_ = nullptr;
    int width_ = 0;
    int height_ = 0;
    float view_matrix_[4][4]{};

    ID3D11Device* device_ = nullptr;
    ID3D11DeviceContext* context_ = nullptr;
    IDXGISwapChain* swap_chain_ = nullptr;
    ID3D11RenderTargetView* rtv_ = nullptr;
};
