#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>
#include <vector>

#include "AhoCorasick/SCAScanningEngine.hpp"
#include "SignaturesDatabase.hpp"

int main() {
  std::cout << "Current working directory: " << std::filesystem::current_path().string() << std::endl;

  SignaturesDatabase database("file_signatures.json");
  database.load();

  const auto signatures = database.getSignatures(SignatureType::Simple);

  std::cout << "Loaded " << signatures.size() << " signatures" << std::endl;

  // Create a 15MB file with random bytes
  // const size_t fileSize = 55 * 1024 * 1024; // 15MB
  const std::string fileName = "random.bin";

  // std::cout << "Creating " << fileSize / (1024 * 1024) << "MB file with random bytes..." << std::endl;

  // // Use random device to generate random bytes
  // std::random_device rd;
  // std::mt19937 gen(rd());
  // std::uniform_int_distribution<unsigned int> dist(0, 255);

  // std::ofstream outFile(fileName, std::ios::binary);
  // if (!outFile) {
  //   std::cerr << "Failed to create file" << std::endl;
  //   return EXIT_FAILURE;
  // }

  // // Write random bytes to file
  // for (size_t i = 0; i < fileSize; ++i) {
  //   uint8_t randomByte = static_cast<uint8_t>(dist(gen));
  //   outFile.write(reinterpret_cast<const char *>(&randomByte), sizeof(randomByte));
  // }
  // outFile.close();

  // std::cout << "File created successfully" << std::endl;

  // Insert our 6-letter pattern "Hello\0" at a specific position
  const std::vector<uint8_t> pattern = {'H', 'e', 'l', 'l', 'o', '\0'};

  std::fstream file(fileName, std::ios::binary | std::ios::in | std::ios::out);
  if (!file) {
    std::cerr << "Failed to open file for writing pattern" << std::endl;
    return EXIT_FAILURE;
  }

  // Create regex engine with multiple patterns
  SCAScanningEngine engine(signatures);

  std::cout << "Searching for pattern in file..." << std::endl;
  auto startTime = std::chrono::high_resolution_clock::now();

  auto result = engine.scanFile(fileName);

  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

  if (result) {
    std::cout << "Pattern found: " << *result << std::endl;
  } else {
    std::cout << "Pattern not found" << std::endl;
  }

  std::cout << "Search completed in " << duration.count() << " ms" << std::endl;

  // Clean up the file
  // std::remove(fileName.c_str());

  return EXIT_SUCCESS;
}