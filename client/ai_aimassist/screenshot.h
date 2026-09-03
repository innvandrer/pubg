#pragma once
#include <Windows.h>
#include <opencv2/opencv.hpp>

class Screenshot {
public:
    Screenshot();
    ~Screenshot();

    cv::Mat& Get();

private:
    HDC         m_hWDC = nullptr;
    HDC         m_hScreen = nullptr;
    HBITMAP     m_hBitmap = nullptr;
    HGDIOBJ     m_hGDI_temp = nullptr;
    BITMAPINFO  m_bitmapinfo{};

    int   m_width = 0;
    int   m_height = 0;
    int   m_left = 0;
    int   m_top = 0;
    char* m_data = nullptr;
    cv::Mat* m_screen = nullptr;
};
