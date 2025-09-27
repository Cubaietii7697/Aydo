#pragma once

#include <botan/hex.h>
#include <cstddef>
#include <vector>

#include "ACNode.hpp"

class AhoCorasick {
private:
  std::shared_ptr<ACNode> root;
  std::vector<std::vector<uint8_t>> patterns;

public:
  explicit AhoCorasick(const std::vector<std::vector<uint8_t>> &patterns);

  [[nodiscard]] std::vector<std::pair<size_t, size_t>> search(const std::vector<uint8_t> &text) const {
    return search(text.data(), text.size());
  }

  [[nodiscard]] std::vector<std::pair<size_t, size_t>> search(const uint8_t *data, size_t length) const;

private:
  void _buildTrie();
  void _buildFaliureLinks();
};
