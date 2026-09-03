#include "imgui.h"

namespace colors {

	inline ImVec4 general_color = ImColor(5, 5, 5, 0);

	namespace background {
		inline ImVec4 background = ImColor(20, 20, 20, 255);
		inline ImVec4 background_left = ImColor(20, 20, 20, 170);
		inline ImVec4 background_border = ImColor(33, 32, 35);
	}

	namespace child {
		inline ImVec4 name_text = ImColor(255, 255, 255, 255);

		inline ImVec4 background = ImColor(23, 25, 24);
		inline ImVec4 background_cap = ImColor(26, 25, 28, 40);
		inline ImVec4 background_border = ImColor(33, 32, 35);

		inline ImVec4 none_text = ImColor(255, 255, 255, 100);
	}

	namespace tabs {

		inline ImVec4 line = ImColor(97, 174, 248);

		inline ImVec4 text_active = ImColor(255, 255, 255, 255);
		inline ImVec4 text_inactive = ImColor(140, 140, 140, 255);

		inline ImVec4 rainbow_active = ImColor(97, 174, 248);
		inline ImVec4 rainbow_inactive = ImColor(60, 225, 120, 0);



	}

	namespace scrollbar {
		inline ImVec4 scroll = ImColor(97, 174, 248);
	}

	namespace checkbox {
		inline ImVec4 status_text = ImColor(0, 0, 0, 255);
		inline ImVec4 scalar = ImColor(34, 34, 34, 255);
		inline ImVec4 background = ImColor(26, 25, 28);
		inline ImVec4 background_active = ImColor(60, 225, 120, 255);

		inline ImVec4 border = ImColor(33, 32, 35);
	}

	namespace slider {

		inline ImVec4 accent = ImColor(60, 225, 120, 255); // GENERAL COLOR

		inline ImVec4 background = ImColor(26, 25, 28);
		inline ImVec4 circle = ImColor(60, 225, 120, 255);
		inline ImVec4 border = ImColor(33, 32, 35);
	}
	namespace combo {

		inline ImVec4 text_active = ImColor(255, 255, 255, 255);
		inline ImVec4 text_hov = ImColor(200, 200, 200, 255);
		inline ImVec4 text = ImColor(108, 108, 108, 255);

		inline ImVec4 background_hov = ImColor(26, 25, 28);
		inline ImVec4 background = ImColor(26, 25, 28);
		inline ImVec4 border = ImColor(33, 32, 35);

		namespace selectable {

		}

	}

	namespace picker {

		inline ImVec4 background = ImColor(26, 25, 28);
		inline ImVec4 border = ImColor(33, 32, 35);
		inline ImVec4 text = ImColor(108, 108, 108, 255);
	}

	namespace keybind {
		inline ImVec4 key_text = ImColor(255, 255, 255);
		inline ImVec4 key_outline = ImColor(33, 32, 35);
		inline ImVec4 key_rect = ImColor(26, 25, 28);
		inline ImVec4 key_window = ImColor(21, 20, 23);
		inline ImVec4 key_window_outline = ImColor(33, 32, 35);

		inline ImVec4 color_outline = ImColor(33, 32, 35);
		inline ImVec4 color_rect = ImColor(26, 25, 28);
	}

	namespace button {

		inline ImVec4 config_ico = ImColor(40, 39, 42);

		inline ImVec4 delete_ico = ImColor(255, 90, 90);

		inline ImVec4 button_text = ImColor(255, 255, 255);
		inline ImVec4 button_outline = ImColor(33, 32, 35);
		inline ImVec4 button_rect = ImColor(26, 25, 28);
		inline ImVec4 button_rect_hov = ImColor(30, 29, 32);

		inline ImVec4 accent = ImColor(60, 225, 120); // GENERAL COLOR
	}

	namespace input {

		inline ImVec4 text_selected = ImColor(35, 35, 35, 100);

		inline ImVec4 button_text = ImColor(255, 255, 255);
		inline ImVec4 button_outline = ImColor(33, 32, 35);
		inline ImVec4 button_rect = ImColor(26, 25, 28);

	}

	namespace text {
		inline ImVec4 text_active = ImColor(255, 255, 255, 255);
		inline ImVec4 text_hov = ImColor(170, 170, 170, 255);
		inline ImVec4 text = ImColor(120, 120, 120, 255);
	}

	namespace separator {
		inline ImVec4 line = ImColor(30, 29, 32);
	}

}
namespace styles {

	namespace background {

		inline ImVec2 size = ImVec2(800, 405);
		inline float border_radius = 1.2f;
		inline float rounding = 5.f;
	}

	namespace child {
		inline float border_radius = 1.2f;
		inline float rounding = 5.f;
	}

	namespace tabs {

	}

	namespace scrollbar {
	}

	namespace checkbox {

		inline float border_radius = 1.2f;
		inline float rounding = 15.f;

	}

	namespace slider {

		inline float border_radius = 1.2f;
		inline float rounding = 25.f;
	}
	namespace combo {

			inline float border_size = 1.2f;
			inline float bg_rounding = 5.f;

	}

	namespace picker {
		inline float rounding = 5.f;
	}

	namespace keybind {
		inline float rounding = 4.f;
	}

	namespace button {
		inline float rounding = 5.f;
	}

	namespace input {
		inline float rounding = 5.f;
	}

}