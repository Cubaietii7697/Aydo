#include "AhoCorasick.hpp"

#include <queue>

AhoCorasick::AhoCorasick(const std::vector<std::vector<uint8_t>> &patterns)
    : patterns(patterns) {
  root = std::make_shared<ACNode>();
  _buildTrie();
  _buildFaliureLinks();
}

void AhoCorasick::_buildTrie() {
  for (size_t i = 0; i < patterns.size(); i++) {
    std::shared_ptr<ACNode> node = root;

    for (uint8_t c : patterns[i]) {
      if (node->children.find(c) == node->children.end()) {
        node->children[c] = std::make_shared<ACNode>();
      }

      node = node->children[c];
    }

    node->output.push_back(i);
  }
}

void AhoCorasick::_buildFaliureLinks() {
  // Initialize queue for BFS traversal of the trie
  std::queue<std::shared_ptr<ACNode>> q;

  // Set failure links for root's direct children to point back to root
  // and add them to the queue for processing
  for (auto &child : root->children) {
    child.second->fail = root;
    q.push(child.second);
  }

  // Process nodes in BFS order to build failure links
  while (!q.empty()) {
    std::shared_ptr<ACNode> node = q.front();
    q.pop();

    // Process each child of the current node
    for (auto &child : node->children) {
      q.push(child.second);

      // Find the appropriate failure link for this child
      // by traversing up the failure chain
      std::shared_ptr<ACNode> fail_node = node->fail;
      while (fail_node && fail_node->children.find(child.first) == fail_node->children.end()) {
        fail_node = fail_node->fail;
      }

      // Set the failure link to the longest proper suffix
      // that exists in the trie, or to root if none found
      if (fail_node && fail_node->children.find(child.first) != fail_node->children.end()) {
        child.second->fail = fail_node->children[child.first];
      } else {
        child.second->fail = root;
      }

      // Merge output patterns from the failure node
      // to ensure all matches are found during search
      for (size_t idx : child.second->fail->output) {
        child.second->output.push_back(idx);
      }
    }
  }
}

// We don't use vectors here because it's slower than raw arrays
std::vector<std::pair<size_t, size_t>> AhoCorasick::search(const uint8_t *data, size_t length) const {
  // Vector to store matches: pair of (pattern_index, end_position_in_text)
  std::vector<std::pair<size_t, size_t>> matches;
  // Start searching from the root of the trie
  std::shared_ptr<ACNode> node = root;

  // Iterate through each byte in the input text
  for (size_t i = 0; i < length; i++) {
    uint8_t byte = data[i];

    // Follow failure links until we find a node that has a child for the current byte
    // or we reach a point where we need to restart from root
    while (node && node->children.find(byte) == node->children.end()) {
      node = node->fail;
    }

    // If we've reached null, restart from root
    // Otherwise, move to the child node that matches the current byte
    if (!node) {
      node = root;
    } else {
      node = node->children.find(byte)->second;
    }

    // Collect all patterns that end at the current node
    // Each pattern index represents a pattern that matches ending at position i
    for (size_t pattern_idx : node->output) {
      matches.emplace_back(pattern_idx, i);
    }
  }

  return matches;
}
