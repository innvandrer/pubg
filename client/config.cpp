#include "config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

static std::string read_string(const std::string& json, const char* key, const std::string& fallback)
{
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find('"', pos);
    if (pos == std::string::npos)
        return fallback;

    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos)
        return fallback;

    return json.substr(pos + 1, end - pos - 1);
}

static float read_float(const std::string& json, const char* key, float fallback)
{
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;

    return std::strtof(json.c_str() + pos + 1, nullptr);
}

static int read_int(const std::string& json, const char* key, int fallback)
{
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;

    return static_cast<int>(std::strtol(json.c_str() + pos + 1, nullptr, 0));
}

static uint64_t read_u64(const std::string& json, const char* key, uint64_t fallback)
{
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;

    return std::strtoull(json.c_str() + pos + 1, nullptr, 0);
}

static bool read_bool(const std::string& json, const char* key, bool fallback)
{
    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return fallback;

    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;

    const std::string tail = json.substr(pos + 1, 8);
    if (tail.find("true") != std::string::npos)
        return true;
    if (tail.find("false") != std::string::npos)
        return false;
    return fallback;
}

bool Config::Load(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file)
        return false;

    std::stringstream ss;
    ss << file.rdbuf();
    const std::string json = ss.str();

    process_name = read_string(json, "process_name", process_name);
    module_name = read_string(json, "module_name", module_name);
    window_title = read_string(json, "window_title", window_title);

    pattern_uworld = read_string(json, "pattern_uworld", pattern_uworld);
    pattern_view_matrix = read_string(json, "pattern_view_matrix", pattern_view_matrix);

    offset_uworld = read_u64(json, "offset_uworld", offset_uworld);
    offset_gnames = read_u64(json, "offset_gnames", offset_gnames);
    offset_view_matrix = read_u64(json, "offset_view_matrix", offset_view_matrix);

    offset_uworld_persistent_level = static_cast<uint32_t>(read_int(json, "offset_uworld_persistent_level", offset_uworld_persistent_level));
    offset_level_actors = static_cast<uint32_t>(read_int(json, "offset_level_actors", offset_level_actors));
    offset_actor_root = static_cast<uint32_t>(read_int(json, "offset_actor_root", offset_actor_root));
    offset_actor_player_name = static_cast<uint32_t>(read_int(json, "offset_actor_player_name", offset_actor_player_name));
    offset_actor_health = static_cast<uint32_t>(read_int(json, "offset_actor_health", offset_actor_health));

    esp_enabled = read_bool(json, "esp_enabled", esp_enabled);
    esp_boxes = read_bool(json, "esp_boxes", esp_boxes);
    esp_health_bar = read_bool(json, "esp_health_bar", esp_health_bar);
    esp_names = read_bool(json, "esp_names", esp_names);
    esp_distance = read_bool(json, "esp_distance", esp_distance);
    esp_max_distance = read_float(json, "esp_max_distance", esp_max_distance);

    esp_color_r = read_int(json, "esp_color_r", esp_color_r);
    esp_color_g = read_int(json, "esp_color_g", esp_color_g);
    esp_color_b = read_int(json, "esp_color_b", esp_color_b);

    key_toggle_menu = read_int(json, "key_toggle_menu", key_toggle_menu);
    key_toggle_esp = read_int(json, "key_toggle_esp", key_toggle_esp);
    key_toggle_health = read_int(json, "key_toggle_health", key_toggle_health);

    ai_enabled = read_bool(json, "ai_enabled", ai_enabled);
    ai_show_detections = read_bool(json, "ai_show_detections", ai_show_detections);
    ai_aim_key = read_int(json, "ai_aim_key", ai_aim_key);
    ai_smooth = read_float(json, "ai_smooth", ai_smooth);
    ai_aim_height = read_float(json, "ai_aim_height", ai_aim_height);
    ai_scan_fps = read_int(json, "ai_scan_fps", ai_scan_fps);
    ai_fov_size = read_int(json, "ai_fov_size", ai_fov_size);
    ai_confidence = read_float(json, "ai_confidence", ai_confidence);
    ai_nms_threshold = read_float(json, "ai_nms_threshold", ai_nms_threshold);
    ai_model_cfg = read_string(json, "ai_model_cfg", ai_model_cfg);
    ai_model_weights = read_string(json, "ai_model_weights", ai_model_weights);
    ai_labels = read_string(json, "ai_labels", ai_labels);

    inject_steam_appid = read_int(json, "inject_steam_appid", inject_steam_appid);
    inject_process_name = read_string(json, "inject_process_name", inject_process_name);
    inject_alt_process_name = read_string(json, "inject_alt_process_name", inject_alt_process_name);
    inject_window_title = read_string(json, "inject_window_title", inject_window_title);
    inject_launch_timeout_ms = read_int(json, "inject_launch_timeout_ms", inject_launch_timeout_ms);
    inject_close_existing = read_bool(json, "inject_close_existing", inject_close_existing);
    inject_stop_terminates_game = read_bool(json, "inject_stop_terminates_game", inject_stop_terminates_game);
    inject_driver_path = read_string(json, "inject_driver_path", inject_driver_path);

    return true;
}

void Config::SaveDefault(const std::string& filename) const
{
    std::ofstream file(filename);
    if (!file)
        return;

    file << "{\n"
         << "  \"process_name\": \"" << process_name << "\",\n"
         << "  \"module_name\": \"" << module_name << "\",\n"
         << "  \"window_title\": \"" << window_title << "\",\n"
         << "  \"pattern_uworld\": \"" << pattern_uworld << "\",\n"
         << "  \"pattern_view_matrix\": \"" << pattern_view_matrix << "\",\n"
         << "  \"offset_uworld\": " << offset_uworld << ",\n"
         << "  \"offset_view_matrix\": " << offset_view_matrix << ",\n"
         << "  \"esp_enabled\": true,\n"
         << "  \"esp_boxes\": true,\n"
         << "  \"esp_health_bar\": true,\n"
         << "  \"esp_names\": true,\n"
         << "  \"esp_distance\": true,\n"
         << "  \"esp_max_distance\": 500.0,\n"
         << "  \"key_toggle_menu\": 45,\n"
         << "  \"key_toggle_esp\": 112,\n"
         << "  \"key_toggle_health\": 113,\n"
         << "  \"ai_enabled\": false,\n"
         << "  \"ai_show_detections\": true,\n"
         << "  \"ai_aim_key\": 114,\n"
         << "  \"ai_smooth\": 30.0,\n"
         << "  \"ai_aim_height\": 50.0,\n"
         << "  \"ai_scan_fps\": 100,\n"
         << "  \"ai_fov_size\": 320,\n"
         << "  \"ai_confidence\": 0.15,\n"
         << "  \"ai_nms_threshold\": 0.35,\n"
         << "  \"ai_model_cfg\": \"runtime\\\\yolov3-tiny.cfg\",\n"
         << "  \"ai_model_weights\": \"runtime\\\\yolov3-tiny.weights\",\n"
         << "  \"ai_labels\": \"runtime\\\\coco-dataset.labels\",\n"
         << "  \"inject_steam_appid\": " << inject_steam_appid << ",\n"
         << "  \"inject_process_name\": \"" << inject_process_name << "\",\n"
         << "  \"inject_alt_process_name\": \"" << inject_alt_process_name << "\",\n"
         << "  \"inject_window_title\": \"" << inject_window_title << "\",\n"
         << "  \"inject_launch_timeout_ms\": " << inject_launch_timeout_ms << ",\n"
         << "  \"inject_close_existing\": " << (inject_close_existing ? "true" : "false") << ",\n"
         << "  \"inject_stop_terminates_game\": " << (inject_stop_terminates_game ? "true" : "false") << ",\n"
         << "  \"inject_driver_path\": \"" << inject_driver_path << "\"\n"
         << "}\n";
}
