#pragma once
#include "defines.h"
#include <opencv2/opencv.hpp>
#include <string>
#include <vector>

class Detector {
public:
    Detector(const std::string& labels_path,
             const std::string& cfg_path,
             const std::string& weights_path);
    ~Detector() = default;

    bool IsLoaded() const { return !net_.empty(); }
    std::string GetBackendName() const { return backend_name_; }

    void SetConfidence(float c) { confidence_ = c; }
    void SetNmsThreshold(float t) { nms_threshold_ = t; }

    void Detect(cv::Mat& frame, float fov_radius, int activation_range,
                std::vector<AiDetection>& boxes, AiDetection& best, bool& have_best);

private:
    void Postprocess(cv::Mat& frame, const std::vector<cv::Mat>& outs,
                     float fov_radius, int activation_range,
                     std::vector<AiDetection>& boxes, AiDetection& best, bool& have_best);
    std::vector<cv::String> GetOutputNames();
    void SetupBackend();

    cv::dnn::Net net_;
    float confidence_ = 0.15f;
    float nms_threshold_ = 0.35f;
    std::vector<std::string> classes_;
    std::string backend_name_ = "CPU";
};
