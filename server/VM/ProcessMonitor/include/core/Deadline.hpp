#pragma once

#include <chrono>

class Deadline {
public:
  explicit Deadline(std::chrono::steady_clock::time_point tp) : tp_(tp) {}

  static Deadline after(std::chrono::milliseconds dur) {
    return Deadline(std::chrono::steady_clock::now() + dur);
  }

  bool expired() const {
    return std::chrono::steady_clock::now() >= tp_;
  }

  std::chrono::milliseconds remaining_ms() const {
    const auto now = std::chrono::steady_clock::now();
    if (now >= tp_) {
      return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp_ - now);
  }

  std::chrono::steady_clock::time_point time_point() const {
    return tp_;
  }

private:
  std::chrono::steady_clock::time_point tp_;
};
