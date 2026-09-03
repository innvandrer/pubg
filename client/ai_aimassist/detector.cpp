#include "detector.h"
#include <cmath>
#include <fstream>
#include <iostream>
#include <opencv2/core/ocl.hpp>

std::vector<cv::String> Detector::GetOutputNames() {
    static std::vector<cv::String> names;
    if (names.empty()) {
        const std::vector<int> out_layers = net_.getUnconnectedOutLayers();
        const std::vector<cv::String> layers = net_.getLayerNames();
        names.resize(out_layers.size());
        for (size_t i = 0; i < out_layers.size(); ++i)
            names[i] = layers[out_layers[i] - 1];
    }
    return names;
}

Detector::Detector(const std::string& labels_path,
                   const std::string& cfg_path,
                   const std::string& weights_path) {
    std::ifstream file(labels_path);
    std::string line;
    while (std::getline(file, line))
        classes_.push_back(line);

    net_ = cv::dnn::readNetFromDarknet(cfg_path, weights_path);
    if (net_.empty())
        return;

    SetupBackend();
}

void Detector::SetupBackend() {
    try {
        net_.setPreferableBackend(cv::dnn::DNN_BACKEND_CUDA);
        net_.setPreferableTarget(cv::dnn::DNN_TARGET_CUDA);
        cv::Mat test = cv::dnn::blobFromImage(
            cv::Mat::zeros(AI_ACTIVATION_RANGE, AI_ACTIVATION_RANGE, CV_8UC3),
            1.0 / 255.0);
        net_.setInput(test);
        std::vector<cv::Mat> outs;
        net_.forward(outs, GetOutputNames());
        if (!outs.empty()) {
            backend_name_ = "CUDA";
            return;
        }
    } catch (...) {
    }

    if (cv::ocl::haveOpenCL()) {
        try {
            cv::ocl::setUseOpenCL(true);
            net_.setPreferableBackend(cv::dnn::DNN_BACKEND_DEFAULT);
            net_.setPreferableTarget(cv::dnn::DNN_TARGET_OPENCL);
            cv::Mat test = cv::dnn::blobFromImage(
                cv::Mat::zeros(AI_ACTIVATION_RANGE, AI_ACTIVATION_RANGE, CV_8UC3),
                1.0 / 255.0);
            net_.setInput(test);
            std::vector<cv::Mat> outs;
            net_.forward(outs, GetOutputNames());
            if (!outs.empty()) {
                backend_name_ = "OpenCL";
                return;
            }
        } catch (...) {
            cv::ocl::setUseOpenCL(false);
        }
    }

    net_.setPreferableBackend(cv::dnn::DNN_BACKEND_DEFAULT);
    net_.setPreferableTarget(cv::dnn::DNN_TARGET_CPU);
    backend_name_ = "CPU";
}

void Detector::Detect(cv::Mat& frame, float fov_radius, int activation_range,
                      std::vector<AiDetection>& boxes, AiDetection& best, bool& have_best) {
    if (net_.empty())
        return;

    cv::Mat blob;
    cv::dnn::blobFromImage(frame, blob, 1.0 / 255.0,
                           cv::Size(activation_range, activation_range),
                           cv::Scalar(0, 0, 0), true, false);
    net_.setInput(blob);
    std::vector<cv::Mat> outs;
    net_.forward(outs, GetOutputNames());
    Postprocess(frame, outs, fov_radius, activation_range, boxes, best, have_best);
}

void Detector::Postprocess(cv::Mat& frame, const std::vector<cv::Mat>& outs,
                           float fov_radius, int activation_range,
                           std::vector<AiDetection>& boxes, AiDetection& best, bool& have_best) {
    std::vector<int> class_ids;
    std::vector<float> confidences;
    std::vector<cv::Rect> rects;

    for (size_t i = 0; i < outs.size(); ++i) {
        float* data = reinterpret_cast<float*>(outs[i].data);
        for (int j = 0; j < outs[i].rows; ++j, data += outs[i].cols) {
            const float objectness = data[4];
            if (objectness < confidence_)
                continue;

            cv::Mat scores = outs[i].row(j).colRange(5, outs[i].cols);
            cv::Point class_id_point;
            double max_class_score;
            cv::minMaxLoc(scores, nullptr, &max_class_score, nullptr, &class_id_point);
            const float confidence = objectness * static_cast<float>(max_class_score);
            if (confidence > confidence_) {
                const int cx = static_cast<int>(data[0] * frame.cols);
                const int cy = static_cast<int>(data[1] * frame.rows);
                const int w  = static_cast<int>(data[2] * frame.cols);
                const int h  = static_cast<int>(data[3] * frame.rows);
                const int x  = cx - w / 2;
                const int y  = cy - h / 2;

                class_ids.push_back(class_id_point.x);
                confidences.push_back(confidence);
                rects.push_back(cv::Rect(x, y, w, h));
            }
        }
    }

    std::vector<int> indices;
    cv::dnn::NMSBoxes(rects, confidences, confidence_, nms_threshold_, indices);

    const float crop_cx = static_cast<float>(frame.cols) * 0.5f;
    const float crop_cy = static_cast<float>(frame.rows) * 0.5f;
    float best_dist = fov_radius;
    have_best = false;

    for (size_t i = 0; i < indices.size(); ++i) {
        const int idx = indices[i];
        const int class_id = class_ids[idx];
        bool is_person = (class_id == 0);
        if (class_id >= 0 && class_id < static_cast<int>(classes_.size()))
            is_person = (classes_[class_id] == "person");
        if (!is_person)
            continue;

        const cv::Rect& r = rects[idx];
        AiDetection det{ r.x, r.y, r.width, r.height };
        boxes.push_back(det);

        const float cx = static_cast<float>(r.x) + static_cast<float>(r.width) * 0.5f;
        const float cy = static_cast<float>(r.y) + static_cast<float>(r.height) * 0.5f;
        const float dx = cx - crop_cx;
        const float dy = cy - crop_cy;
        const float dist = std::sqrt(dx * dx + dy * dy);
        if (dist < best_dist) {
            best_dist = dist;
            best = det;
            have_best = true;
        }
    }
}
