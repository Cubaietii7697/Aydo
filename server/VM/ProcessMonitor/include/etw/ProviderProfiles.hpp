#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace ProviderProfiles {

inline constexpr std::size_t g_ANALYST_USER_PROVIDER_COUNT = 11;

const std::array<const wchar_t *, g_ANALYST_USER_PROVIDER_COUNT> &getAnalystUserProviders();

bool isForbiddenProvider(std::wstring_view providerName);

} // namespace ProviderProfiles

