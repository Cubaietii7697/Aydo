#include <iostream>
#include <random>

#include "AhoCorasick/ACScanningEngine.hpp"

int main() {
  try {
    ACScanningEngine engine({"AA ?? CC ?? BB"}, 1024 * 1024);

    std::vector<unsigned char> data(1024 * 1024 * 100);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    for (unsigned char &i : data) {
      i = static_cast<unsigned char>(dist(gen));
    }

    std::cout << "Done creating data" << std::endl;

    auto result = engine.scanMemory(data);

    if (result) {
      std::cout << "Pattern (" << result.value() << ") found" << std::endl;
    } else {
      std::cout << "Pattern not found" << std::endl;
    }

  } catch (const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << std::endl;

    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}