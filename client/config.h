#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

struct Config {
    std::string process_name = "TslGame.exe";
    std::string module_name = "TslGame.exe";
    std::string window_title = "PUBG";

    /* Pattern strings (IDA style). Update after each game patch. */
    std::string pattern_uworld = "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9";
    std::string pattern_view_matrix = "48 8D 0D ? ? ? ? 48 C1 E0 06";

    /* Optional hardcoded offsets (skip scan when non-zero). */
    uint64_t offset_uworld = 0;
    uint64_t offset_gnames = 0;
    uint64_t offset_view_matrix = 0;

    /* UE4 chain offsets inside structures — patch via RE. */
    uint32_t offset_uworld_persistent_level = 0x30;
    uint32_t offset_level_actors = 0x98;
    uint32_t offset_actor_root = 0x130;
    uint32_t offset_actor_player_name = 0x438;
    uint32_t offset_actor_health = 0x980;

    /* ESP */
    bool esp_enabled = true;
    bool esp_boxes = true;
    bool esp_health_bar = true;
    bool esp_names = true;
    bool esp_distance = true;
    float esp_max_distance = 500.f;
    int esp_color_r = 255;
    int esp_color_g = 64;
    int esp_color_b = 64;

    /* Keybinds — virtual-key codes */
    int key_toggle_menu = VK_INSERT;
    int key_toggle_esp = VK_F1;
    int key_toggle_health = VK_F2;

    /* AI aim assist */
    bool ai_enabled = false;
    bool ai_show_detections = true;
    int ai_aim_key = VK_F3;
    float ai_smooth = 30.0f;
    float ai_aim_height = 50.0f;
    int ai_scan_fps = 100;
    int ai_fov_size = 320;
    float ai_confidence = 0.15f;
    float ai_nms_threshold = 0.35f;
    std::string ai_model_cfg = "runtime\\\\yolov3-tiny.cfg";
    std::string ai_model_weights = "runtime\\\\yolov3-tiny.weights";
    std::string ai_labels = "runtime\\\\coco-dataset.labels";

    bool show_menu = false;

    // One-click Steam inject flow settings
    int inject_steam_appid = 578080;
    std::string inject_process_name = "TslGame.exe";
    std::string inject_alt_process_name = "PUBG_BATTLEGROUNDS.exe";
    std::string inject_window_title = "PUBG";
    int inject_launch_timeout_ms = 120000;
    bool inject_close_existing = true;
    bool inject_stop_terminates_game = true;
    std::string inject_driver_path = "x64\\Release\\MyMemoryDriver.sys";

    bool Load(const std::string& filename);
    void SaveDefault(const std::string& filename) const;
};
