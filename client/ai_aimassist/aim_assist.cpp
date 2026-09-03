#include "aim_assist.h"
#include "config.h"
#include "defines.h"
#include "detector.h"
#include "mouse_input.h"
#include "screenshot.h"
#include <cmath>

AimAssist::AimAssist(const Config& config) : config_(config) {}

AimAssist::~AimAssist() {
    Stop();
}

bool AimAssist::Initialize(const std::string& base_dir) {
    base_dir_ = base_dir;

    const std::string labels  = base_dir_ + "\\" + config_.ai_labels;
    const std::string cfg     = base_dir_ + "\\" + config_.ai_model_cfg;
    const std::string weights = base_dir_ + "\\" + config_.ai_model_weights;

    detector_ = std::make_unique<Detector>(labels, cfg, weights);
    if (!detector_->IsLoaded())
        return false;

    backend_name_ = detector_->GetBackendName();
    screen_ = std::make_unique<Screenshot>();
    initialized_ = true;
    return true;
}

void AimAssist::Start() {
    if (!initialized_ || running_)
        return;
    running_ = true;
    thread_ = std::thread(&AimAssist::RunLoop, this);
}

void AimAssist::Stop() {
    running_ = false;
    if (thread_.joinable())
        thread_.join();
}

bool AimAssist::IsEnabled() const {
    return config_.ai_enabled;
}

std::vector<AiDetection> AimAssist::GetDetections() const {
    std::lock_guard<std::mutex> lock(detections_mutex_);
    return detections_;
}

void AimAssist::AimAt(const AiDetection& target) {
    const int screen_w = GetSystemMetrics(SM_CXSCREEN);
    const int screen_h = GetSystemMetrics(SM_CYSCREEN);

    const int crop_left = screen_w / 2 - AI_ACTIVATION_RANGE / 2;
    const int crop_top  = screen_h / 2 - AI_ACTIVATION_RANGE / 2;

    const int aim_x = crop_left + target.x + target.w / 2 + 5;
    const int aim_y = crop_top + target.y + (101 - static_cast<int>(config_.ai_aim_height)) + target.h / 4;

    const int x_offset = aim_x - screen_w / 2;
    const int y_offset = aim_y - screen_h / 2;

    const double cursor_speed = config_.ai_smooth / 10.0;
    const int move_x = static_cast<int>(x_offset / cursor_speed);
    const int move_y = static_cast<int>(y_offset / cursor_speed);

    static double x_smooth = 0.0;
    static double y_smooth = 0.0;
    const double smoothing = 0.05;

    x_smooth = smoothing * x_smooth + (1.0 - smoothing) * move_x;
    y_smooth = smoothing * y_smooth + (1.0 - smoothing) * move_y;

    const double acceleration = 0.1;
    x_smooth += (move_x - x_smooth) * acceleration;
    y_smooth += (move_y - y_smooth) * acceleration;

    MouseInput mouse;
    mouse.Move(static_cast<int>(x_smooth), static_cast<int>(y_smooth));
}

void AimAssist::RunLoop() {
    if (!detector_ || !screen_)
        return;

    while (running_) {
        const bool aim_held = (GetAsyncKeyState(config_.ai_aim_key) & 0x8000) != 0;

        if (config_.ai_enabled && (aim_held || config_.ai_show_detections)) {
            cv::Mat frame = screen_->Get();

            detector_->SetConfidence(config_.ai_confidence);
            detector_->SetNmsThreshold(config_.ai_nms_threshold);

            std::vector<AiDetection> boxes;
            AiDetection best{};
            bool have_best = false;

            detector_->Detect(frame, static_cast<float>(config_.ai_fov_size),
                              AI_ACTIVATION_RANGE, boxes, best, have_best);

            {
                std::lock_guard<std::mutex> lock(detections_mutex_);
                detections_ = std::move(boxes);
                fov_size_ = config_.ai_fov_size;
            }

            if (aim_held && have_best)
                AimAt(best);

            int delay = 251 - config_.ai_scan_fps;
            if (delay < 1)
                delay = 1;
            Sleep(static_cast<DWORD>(delay));
        } else {
            {
                std::lock_guard<std::mutex> lock(detections_mutex_);
                detections_.clear();
            }
            Sleep(10);
        }
    }
}
