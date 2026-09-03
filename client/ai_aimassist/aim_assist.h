#pragma once
#include <Windows.h>
#include "defines.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class Detector;
class Screenshot;

struct Config;

class AimAssist {
public:
    explicit AimAssist(const Config& config);
    ~AimAssist();

    bool Initialize(const std::string& base_dir);
    void Start();
    void Stop();

    bool IsEnabled() const;
    std::string GetBackendName() const { return backend_name_; }

    std::vector<AiDetection> GetDetections() const;
    int GetFovSize() const { return fov_size_.load(); }

private:
    void RunLoop();
    void AimAt(const AiDetection& target);

    const Config& config_;
    std::thread thread_;
    std::atomic<bool> running_{ false };
    std::atomic<bool> initialized_{ false };
    std::atomic<int> fov_size_{ 320 };

    std::vector<AiDetection> detections_;
    mutable std::mutex detections_mutex_;
    std::string backend_name_ = "CPU";
    std::string base_dir_;
    std::unique_ptr<Detector> detector_;
    std::unique_ptr<Screenshot> screen_;
};
