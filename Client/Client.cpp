#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

constexpr std::string_view BANNER = R"(
   ___ ___ _  _ ___ _   _ ___ 
  / __| __| \| |_ _| | | / __|
 | (_ | _|| .` || || |_| \__ \
  \___|___|_|\_|___|\___/|___/
                              
)";

// Rainbow colors for console output
const std::vector<WORD> rainbowColors = {
    FOREGROUND_RED | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY};

void setConsoleColor(WORD color) {
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void printRainbowText(const std::string &text) {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(hConsole, &csbi);

  WORD defaultColor = csbi.wAttributes;

  for (size_t i = 0; i < text.length(); ++i) {
    setConsoleColor(rainbowColors[i % rainbowColors.size()]);
    std::cout << text[i];
  }

  setConsoleColor(defaultColor);
}

void printRainbowBanner() {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  GetConsoleScreenBufferInfo(hConsole, &csbi);

  WORD defaultColor = csbi.wAttributes;
  std::string bannerStr(BANNER);

  for (size_t i = 0; i < bannerStr.length(); ++i) {
    if (bannerStr[i] != '\n' && bannerStr[i] != ' ') {
      setConsoleColor(rainbowColors[i % rainbowColors.size()]);
    } else {
      setConsoleColor(defaultColor);
    }
    std::cout << bannerStr[i];
  }

  setConsoleColor(defaultColor);
}

int main() {
  while (true) {
    printRainbowText("Itay is a");
    std::cout << std::endl;
    printRainbowBanner();
    std::cout << std::endl;

    Sleep(100);
  }

  return EXIT_SUCCESS;
}