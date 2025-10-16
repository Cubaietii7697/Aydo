#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

// Each node in the Aho-Corasick trie can have multiple children (not like a regular tree)
// Each node has a fail pointer to the longest proper prefix which is also a suffix
// Each node has an output vector to store the indexes of the patterns that end at that node
class ACNode {
public:
  std::map<uint8_t, std::shared_ptr<ACNode>> children;
  std::shared_ptr<ACNode> fail = nullptr;
  std::vector<size_t> output;

  ACNode() = default;
  ~ACNode() = default;
};
